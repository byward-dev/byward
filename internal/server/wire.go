package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/denylist"
	"github.com/byward-dev/byward/internal/gate"
	"github.com/byward-dev/byward/internal/health"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/mcpsession"
	"github.com/byward-dev/byward/internal/ratelimit"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/secretfile"
	"github.com/byward-dev/byward/internal/ssrfguard"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
	"github.com/byward-dev/byward/internal/token"
)

// maxRateLimitKeys bounds the client addresses each OAuth endpoint tracks (ADR-0018 §8).
const maxRateLimitKeys = 100000

// maxJTIs bounds the in-memory private_key_jwt replay cache.
const maxJTIs = 10000

// auth is what authenticated mode adds: the broker's routes, the access-token validator and the
// readiness checks for its keys and store.
type auth struct {
	register  func(*http.ServeMux)
	validator resource.Validator
	checks    []health.Check
	// background runs until ctx ends: it keeps the revocation list fresh (ADR-0006 §3) and removes
	// expired store rows (ADR-0007 §1).
	background func(ctx context.Context)
	// closeStore releases the store; Run calls it after the background work has stopped.
	closeStore func() error
	// sessions binds legacy-era MCP sessions to the user (ADR-0004 §2, invariant 13).
	sessions func(http.Handler) http.Handler
}

// idpName names the IdP adapter in its callback path, the broker and metrics.
const idpName = "entra"

// pinger is a store that can say whether it is reachable, for readiness.
type pinger interface{ Ping(context.Context) error }

// buildAuth wires the broker: sealing keys, Entra, static clients, the access gate and the SQLite
// store. Errors name the file or setting at fault.
func buildAuth(cfg *config.Config, log *slog.Logger, o Observability) (_ *auth, err error) {
	logPaths(cfg, log)
	ring, err := token.LoadKeyRing(cfg.KeysDir)
	if err != nil {
		// No key generation (ADR-0007 §5): the operator creates the first key.
		return nil, fmt.Errorf("BYWARD_KEYS_DIR: %s: %w (see docs/how-to/sealing-keys.md)", cfg.KeysDir, err)
	}
	resourceURL := cfg.PublicURL.String()
	sealer, err := token.NewSealer(ring, resourceURL)
	if err != nil {
		return nil, err
	}
	loginBox, err := token.NewBox(ring, "login", nil)
	if err != nil {
		return nil, err
	}
	idpBox, err := token.NewBox(ring, "idp-tokens", nil)
	if err != nil {
		return nil, err
	}
	consentBox, err := token.NewBox(ring, "consent", nil)
	if err != nil {
		return nil, err
	}
	sessionBox, err := token.NewBox(ring, "mcp-session", nil)
	if err != nil {
		return nil, err
	}
	checkSecret := secretfile.Check
	if cfg.Dev {
		checkSecret = func(string) error { return nil }
	}
	var loose []error // every loose secret file and the static clients' error, reported at once
	for _, f := range cfg.Values.SecretFiles() {
		if err := checkSecret(f.Path); err != nil {
			loose = append(loose, fmt.Errorf("%s: %w", f.From, err))
		}
	}
	jti := registration.NewMemoryJTICache(time.Now, maxJTIs)
	static, err := registration.LoadStatic(cfg.StaticClientsFile, os.ReadFile, jti, registration.WithSecretCheck(checkSecret))
	if err != nil {
		loose = append(loose, fmt.Errorf("BYWARD_STATIC_CLIENTS_FILE: %s: %w (see docs/reference/static-clients.md)", cfg.StaticClientsFile, err))
	}
	if err := errors.Join(loose...); err != nil {
		return nil, err
	}
	auditStartup(o.Audit, ring, static.IDs())
	var clients registration.Registry = static
	if cfg.CIMD {
		guard := ssrfguard.New(ssrfguard.Config{})
		clients = registration.Chain{static, newCIMDRegistry(registration.CIMDConfig{Fetch: guard, KeysClient: guard.HTTPClient(),
			TrustedHosts: cfg.CIMDTrustedHosts, AllowedHosts: cfg.CIMDAllowedHosts, JTI: jti, Now: time.Now, Observe: o.Metrics.CIMDFetch})}
	}
	provider, err := entra.New(entra.Config{Tenant: cfg.EntraTenant, ClientID: cfg.EntraClientID,
		ClientAuth: idp.ClientSecret(cfg.EntraClientSecret), RedirectURL: cfg.Issuer() + "/callback/" + idpName})
	if err != nil {
		return nil, fmt.Errorf("entra settings (BYWARD_ENTRA_*): %w", err)
	}
	g, warnings, err := gate.New(gate.Rules{Tenants: cfg.GateTenants, Roles: cfg.GateRoles, Groups: cfg.GateGroups,
		EmailDomains: cfg.GateEmailDomains, HostedDomains: cfg.GateHostedDomains},
		gate.Options{IdP: gate.Entra, Tenant: cfg.EntraTenant, AllowEmpty: cfg.GateAllowEmpty})
	if err != nil {
		return nil, gateError(err)
	}
	for _, w := range warnings {
		log.Warn(w)
	}
	st, err := wireStore(cfg, log, o.Audit)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = st.Close()
		}
	}()
	b, err := newBroker(broker.Config{Issuer: cfg.Issuer(), Origin: cfg.Origin(), Resource: cfg.PublicURL, Scope: cfg.Scope,
		IdPName: idpName, IdPLabel: "Microsoft Entra", IdPScopes: provider.Scope(), IdP: provider, Clients: clients, CIMD: cfg.CIMD,
		Store: st, Sealer: sealer, LoginBox: loginBox, IdPTokenBox: idpBox, ConsentBox: consentBox, Gate: g,
		UpstreamName: cfg.ResourceName, ScopeText: cfg.ScopeDescription, OperatorName: cfg.OperatorName,
		SecureCookies: cfg.PublicURL.Scheme == "https", Log: log,
		Audit: o.Audit, Limiter: ratelimit.New(cfg.OAuthRateLimits, maxRateLimitKeys, time.Now, o.Metrics.RateLimited),
		ObserveIdP:   func(op, outcome string, d time.Duration) { o.Metrics.IdP(idpName, op, outcome, d) },
		RefreshGrace: cfg.RefreshGrace})
	if err != nil {
		return nil, err
	}
	deny := b.Deny()
	// The list refuses every token until its first sync, so sync before serving.
	syncCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := deny.Sync(syncCtx); err != nil {
		return nil, fmt.Errorf("loading the revocation list: %w", err)
	}
	v, err := token.NewValidator(sealer, deny, nil)
	if err != nil {
		return nil, err
	}
	if cfg.ScopeDescription == "" {
		log.Warn("consent page uses generic wording", "setting", "BYWARD_SCOPE_DESCRIPTION",
			"reason", "set it to say in plain words what the "+cfg.Scope+" scope lets an app do (ADR-0010 §4)")
	}
	log.Info("broker ready", "reason", "keys "+fmt.Sprint(len(ring.KeyIDs()))+", signing with "+ring.SigningKeyID()+"")
	return &auth{register: b.Register, validator: v, checks: readiness(ring, st), background: func(ctx context.Context) { runBackground(ctx, st, deny, log) }, closeStore: st.Close,
		sessions: func(next http.Handler) http.Handler {
			return mcpsession.Bind(mcpsession.Config{Box: sessionBox, Upstream: cfg.UpstreamURL.String(), User: signedInUser,
				Lifetime: broker.GrantLifetime, Audit: o.Audit, Log: log}, next)
		}}, nil
}

// auditStartup records the keys and static clients the proxy starts with (ADR-0021 §3).
func auditStartup(rec *audit.Log, ring *token.KeyRing, staticClients []string) {
	for _, id := range ring.KeyIDs() {
		use := "verification"
		if id == ring.SigningKeyID() {
			use = "signing"
		}
		rec.Record(nil, audit.Event{Name: audit.KeyLoaded, Outcome: audit.Success, Reason: use, KeyID: id})
	}
	for _, id := range staticClients {
		rec.Record(nil, audit.Event{Name: audit.ClientRegistered, Outcome: audit.Success, Reason: "static", ClientID: id})
	}
}

// readiness is what /readyz checks in authenticated mode: a signing key and the store. Never the
// IdP (ADR-0021 §10).
func readiness(ring *token.KeyRing, st pinger) []health.Check {
	checks := []health.Check{{Name: "keys", Ready: func(context.Context) error {
		if ring.SigningKeyID() == "" {
			return errors.New("no signing key")
		}
		return nil
	}}}
	return append(checks, health.Check{Name: "store", Ready: st.Ping})
}

// signedInUser is the access token's subject, which Guard attached to the request.
func signedInUser(r *http.Request) (string, bool) {
	id, ok := resource.IdentityFrom(r.Context())
	return id.Subject, ok && id.Subject != ""
}

// newCIMDRegistry is registration.NewCIMDRegistry; tests replace it to see the wired host lists.
var newCIMDRegistry = registration.NewCIMDRegistry

// newBroker is broker.New; tests replace it to see the wired configuration.
var newBroker = broker.New

// wireStore is openStore; tests replace it to reach the wired store.
var wireStore = openStore

// collectEvery is how often expired store rows are removed (ADR-0007 §1): grants, codes, refresh
// tokens and revocations older than store.RevocationRetention.
const collectEvery = 5 * time.Minute

// runBackground keeps the revocation list fresh and removes expired store rows until ctx ends,
// and returns only when both have stopped, so Run closes the store after the last write.
func runBackground(ctx context.Context, st store.Collector, deny *denylist.List, log *slog.Logger) {
	var wg sync.WaitGroup
	wg.Go(func() { collect(ctx, st, log) })
	deny.Run(ctx, log)
	wg.Wait()
}

// collect runs store.Collect now and every collectEvery until ctx ends; a failure is logged and
// retried at the next tick.
func collect(ctx context.Context, st store.Collector, log *slog.Logger) {
	t := time.NewTicker(collectEvery)
	defer t.Stop()
	for {
		if err := st.Collect(ctx, time.Now()); err != nil && ctx.Err() == nil {
			log.ErrorContext(ctx, "removing expired store rows failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// gateSettings maps gate rule lists to the settings that fill them; config owns the names.
var gateSettings = map[string]string{
	gate.FieldTenants:       config.Setting{Name: "gate-tenants"}.Env(),
	gate.FieldRoles:         config.Setting{Name: "gate-roles"}.Env(),
	gate.FieldGroups:        config.Setting{Name: "gate-groups"}.Env(),
	gate.FieldEmailDomains:  config.Setting{Name: "gate-email-domains"}.Env(),
	gate.FieldHostedDomains: config.Setting{Name: "gate-hosted-domains"}.Env(),
	gate.FieldAllowEmpty:    config.Setting{Name: "gate-allow-empty"}.Env(),
}

// gateError names the setting at fault for each invalid gate rule list.
func gateError(err error) error {
	errs := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		errs = j.Unwrap()
	}
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		var fe *gate.FieldError
		if errors.As(e, &fe) && gateSettings[fe.Field] != "" {
			msgs = append(msgs, gateSettings[fe.Field]+": "+fe.Msg)
			continue
		}
		msgs = append(msgs, "access gate: "+e.Error())
	}
	return errors.New(strings.Join(msgs, "; "))
}

// logPaths logs the absolute paths the proxy uses, defaults resolved (ADR-0007 §6).
func logPaths(cfg *config.Config, log *slog.Logger) {
	for _, p := range []struct{ setting, value string }{
		{"BYWARD_DATA_DIR", cfg.DataDir}, {"BYWARD_KEYS_DIR", cfg.KeysDir},
		{"BYWARD_STATIC_CLIENTS_FILE", cfg.StaticClientsFile}, {"BYWARD_STORE_DIR", cfg.StoreDir},
		{"BYWARD_STORE_COUNTER_FILE", cfg.StoreCounterFile},
	} {
		log.Info("path", "setting", p.setting, "value", p.value)
	}
}

// openStore opens the SQLite store and reports what it found (ADR-0007 §9): a database behind its
// counter file was restored from an older copy, so the store started a new epoch and refresh
// tokens from before the restore no longer work; users sign in again.
func openStore(cfg *config.Config, log *slog.Logger, rec *audit.Log) (*sqlite.Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := sqlite.Open(ctx, sqlite.Options{Dir: cfg.StoreDir, CounterFile: cfg.StoreCounterFile})
	if err != nil {
		return nil, fmt.Errorf("BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: %w", err)
	}
	s := st.Startup()
	switch {
	case s.Restored:
		log.Warn("store restored from an older copy: a new epoch started, refresh tokens issued before the restore are refused and their users sign in again",
			"reason", "store_restore", "epoch", s.Epoch, "setting", "BYWARD_STORE_DIR", "value", cfg.StoreDir)
		rec.Record(nil, audit.Event{Name: audit.StoreRestored, Outcome: audit.Success, Reason: "restored from an older copy", Epoch: s.Epoch})
	case s.CounterMissing:
		log.Warn("store counter file missing: a restore of the state directory could not be detected at this start",
			"reason", "store_counter_missing", "setting", "BYWARD_STORE_COUNTER_FILE", "value", cfg.StoreCounterFile)
	}
	log.Info("store open", "setting", "BYWARD_STORE_DIR", "value", cfg.StoreDir, "epoch", s.Epoch)
	return st, nil
}
