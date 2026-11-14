package server

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"

	"github.com/byward-dev/byward/internal/assertion"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/gate"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/secretfile"
	"github.com/byward-dev/byward/internal/token"
)

// authParts is what authenticated mode builds from configuration alone, with no network access and
// no writes; check --offline stops here (ADR-0020 §7).
type authParts struct {
	ring                                  *token.KeyRing
	sealer                                *token.Sealer
	loginBox, idpBox, consentBox, hintBox *token.Box
	sessionBox                            *token.Box
	static                                *registration.StaticRegistry
	// jti is the private_key_jwt replay cache, shared by static, CIMD and DCR clients. It keeps its
	// IDs in the store, which buildAuth binds once it is open.
	jti *registration.StoreJTICache
	// clientDeny is BYWARD_CLIENT_DENYLIST, applied to CIMD and DCR clients.
	clientDeny *registration.Denylist
	// assertionKeys sign the identity assertion for an HTTP upstream; nil for a stdio upstream.
	assertionKeys *assertion.Keys
	idp           *identityProvider
	gate          *gate.Gate
	// appGate admits app-only callers; nil while BYWARD_APP_TOKENS is off.
	appGate *gate.AppGate
	// warnings are logged at every start and reported by check and doctor.
	warnings []Warning
}

// Warning is a configuration that works but that the operator should look at. Setting and Fix are
// empty for warnings that come from a package with its own wording (the access gate's).
type Warning struct {
	Message string
	Setting string
	Fix     string
}

func (w Warning) log(log *slog.Logger) {
	if w.Setting == "" {
		log.Warn(w.Message)
		return
	}
	log.Warn(w.Message, "setting", w.Setting, "reason", w.Fix)
}

// String is the warning on one line, for check and doctor.
func (w Warning) String() string {
	if w.Setting == "" {
		return w.Message
	}
	return w.Message + " (" + w.Setting + ": " + w.Fix + ")"
}

// loadAuthParts reads the sealing keys and the static clients and validates the IdP and gate
// settings. Errors name the file or setting at fault. idpHTTP reaches the IdP; nil is the default
// client (tests give a fake's).
func loadAuthParts(cfg *config.Config, idpHTTP *http.Client) (*authParts, error) {
	ring, err := token.LoadKeyRing(cfg.KeysDir)
	if err != nil {
		// No key generation (ADR-0007 §5): the operator creates the first key.
		return nil, fmt.Errorf("BYWARD_KEYS_DIR: %s: %w (see docs/how-to/sealing-keys.md)", cfg.KeysDir, err)
	}
	p := &authParts{ring: ring}
	if p.sealer, err = token.NewSealer(ring, cfg.PublicURL.String()); err != nil {
		return nil, err
	}
	for _, b := range []struct {
		box     **token.Box
		purpose string
	}{{&p.loginBox, "login"}, {&p.idpBox, "idp-tokens"}, {&p.consentBox, "consent"}, {&p.hintBox, "consent-hint"}, {&p.sessionBox, "mcp-session"}} {
		if *b.box, err = token.NewBox(ring, b.purpose, nil); err != nil {
			return nil, err
		}
	}
	checkSecret := secretCheck(cfg)
	loose := looseSecretFiles(cfg) // with the static clients' error below, reported at once
	p.jti = registration.NewStoreJTICache(nil)
	opts := []registration.LoadOption{registration.WithSecretCheck(checkSecret)}
	if cfg.CIMD || cfg.DCR { // apps can register themselves, so no static client is needed
		opts = append(opts, registration.AllowNoClients())
		// A file the operator named must exist, so a typo fails here. At the default path only nothing
		// at all counts as absent: a dangling symlink (a broken mount) still fails.
		if _, err := os.Lstat(cfg.StaticClientsFile); !cfg.StaticClientsFileNamed && errors.Is(err, fs.ErrNotExist) {
			opts = append(opts, registration.AllowMissingFile())
		}
	}
	p.static, err = registration.LoadStatic(cfg.StaticClientsFile, os.ReadFile, p.jti, opts...)
	if err != nil {
		loose = append(loose, fmt.Errorf("BYWARD_STATIC_CLIENTS_FILE: %s: %w (see docs/reference/static-clients.md)", cfg.StaticClientsFile, err))
	}
	if err := errors.Join(loose...); err != nil {
		return nil, err
	}
	if p.clientDeny, err = registration.NewDenylist(cfg.ClientDenylist); err != nil {
		return nil, fmt.Errorf("BYWARD_CLIENT_DENYLIST: %w", err)
	}
	if cfg.UpstreamCommand == nil { // only an HTTP upstream gets the assertion (ADR-0016 §2, §6)
		if p.assertionKeys, err = assertion.LoadKeys(cfg.AssertionKeysDir, secretCheck(cfg)); err != nil {
			// No key generation (ADR-0007 §5, ADR-0016 §10): the operator creates the first key.
			return nil, fmt.Errorf("BYWARD_ASSERTION_KEYS_DIR: %s: %w (see docs/how-to/identity-assertion.md)", cfg.AssertionKeysDir, err)
		}
	}
	if p.idp, err = newIdentityProvider(cfg, idpHTTP); err != nil {
		return nil, err
	}
	p.warnings = append(p.warnings, p.idp.warnings...)
	var gateWarnings []string
	p.gate, gateWarnings, err = gate.New(gate.Rules{Tenants: cfg.GateTenants, Roles: cfg.GateRoles, Groups: cfg.GateGroups,
		EmailDomains: cfg.GateEmailDomains, HostedDomains: cfg.GateHostedDomains},
		gate.Options{IdP: p.idp.gateIdP, Tenant: cfg.EntraTenant, AllowEmpty: cfg.GateAllowEmpty})
	if err != nil {
		return nil, gateError(err)
	}
	for _, w := range gateWarnings {
		p.warnings = append(p.warnings, Warning{Message: w})
	}
	if cfg.UpstreamCommand == nil { // a stdio upstream gets no assertion and no email (ADR-0016 §6)
		p.warnings = append(p.warnings, emailWarnings(cfg, p.idp.gateIdP == gate.Entra)...)
	}
	if cfg.AppTokens == "entra" {
		if p.idp.appTokens == nil {
			return nil, errors.New("BYWARD_APP_TOKENS=entra needs BYWARD_IDP=entra")
		}
		if p.appGate, err = gate.NewApp(gate.AppRules{Roles: cfg.AppRoles, ClientIDs: cfg.AppClientIDs, Tenants: cfg.GateTenants}); err != nil {
			return nil, gateError(err)
		}
	}
	if w := isolationWarning(cfg, hostPtraceWarning); w != nil {
		p.warnings = append(p.warnings, *w)
	}
	if cfg.ScopeDescription == "" {
		p.warnings = append(p.warnings, Warning{Message: "consent page uses generic wording", Setting: "BYWARD_SCOPE_DESCRIPTION",
			Fix: "set it to say in plain words what the " + cfg.Scope + " scope lets an app do (ADR-0010 §4)"})
	}
	return p, nil
}

// secretCheck is the permission check for secret files (ADR-0018 §11); --dev turns it off.
func secretCheck(cfg *config.Config) func(string) error {
	if cfg.Dev {
		return func(string) error { return nil }
	}
	return secretfile.Check
}

// looseSecretFiles is one error per secret file other users can read (the TLS key's included),
// named by its setting, and for the federated token file (read at each request, not at start) one if it is missing.
func looseSecretFiles(cfg *config.Config) []error {
	check := secretCheck(cfg)
	var loose []error
	for _, f := range cfg.Values.SecretFiles() {
		if err := check(f.Path); err != nil {
			loose = append(loose, fmt.Errorf("%s: %w", f.From, err))
		}
	}
	if f := cfg.TLSKeyFile; f != "" {
		if err := check(f); err != nil {
			loose = append(loose, fmt.Errorf("%s: %w", tlsKeyEnv, err))
		}
	}
	// A federated token is a credential too, though it is read at each request, not at start.
	if f := cfg.EntraFederatedTokenFile; f != "" {
		// It must exist even in --dev, as every other secret file must to be read at start.
		if _, err := os.Stat(f); err != nil {
			loose = append(loose, fmt.Errorf("%s: %w", config.Setting{Name: "entra-federated-token-file"}.Env(), err))
		} else if err := check(f); err != nil {
			loose = append(loose, fmt.Errorf("%s: %w", config.Setting{Name: "entra-federated-token-file"}.Env(), err))
		}
	}
	return loose
}
