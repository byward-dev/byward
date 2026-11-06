package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/broker"
	"github.com/corker/mcp-authproxy/internal/config"
	"github.com/corker/mcp-authproxy/internal/gate"
	"github.com/corker/mcp-authproxy/internal/health"
	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/idp/entra"
	"github.com/corker/mcp-authproxy/internal/ratelimit"
	"github.com/corker/mcp-authproxy/internal/registration"
	"github.com/corker/mcp-authproxy/internal/resource"
	"github.com/corker/mcp-authproxy/internal/store"
	"github.com/corker/mcp-authproxy/internal/store/memory"
	"github.com/corker/mcp-authproxy/internal/token"
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
	// background runs until ctx ends: it keeps the revocation list fresh (ADR-0006 §3).
	background func(ctx context.Context)
}

// idpName names the IdP adapter in its callback path, the broker and metrics.
const idpName = "entra"

// pinger is a store that can say whether it is reachable; the in-memory store has nothing to check.
type pinger interface{ Ping(context.Context) error }

// buildAuth wires the broker (slice 1.2): sealing keys, Entra, static clients and the in-memory
// store (SQLite arrives with slice 1.3). Errors name the file or setting at fault.
func buildAuth(cfg *config.Config, log *slog.Logger, o Observability) (*auth, error) {
	ring, err := token.LoadKeyRing(cfg.KeysDir)
	if err != nil {
		return nil, fmt.Errorf("MCP_AUTHPROXY_KEYS_DIR: %w", err)
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
	clients, err := registration.LoadStatic(cfg.StaticClientsFile, os.ReadFile, registration.NewMemoryJTICache(time.Now, maxJTIs))
	if err != nil {
		return nil, fmt.Errorf("MCP_AUTHPROXY_STATIC_CLIENTS_FILE: %w", err)
	}
	auditStartup(o.Audit, ring, clients.IDs())
	provider, err := entra.New(entra.Config{Tenant: cfg.EntraTenant, ClientID: cfg.EntraClientID,
		ClientAuth: idp.ClientSecret(cfg.EntraClientSecret), RedirectURL: cfg.Issuer() + "/callback/" + idpName})
	if err != nil {
		return nil, fmt.Errorf("entra settings (MCP_AUTHPROXY_ENTRA_*): %w", err)
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
	st := memory.New()
	b, err := newBroker(broker.Config{Issuer: cfg.Issuer(), Origin: cfg.Origin(), Resource: cfg.PublicURL, Scope: cfg.Scope,
		IdPName: idpName, IdPLabel: "Microsoft Entra", IdPScopes: provider.Scope(), IdP: provider, Clients: clients,
		Store: st, Sealer: sealer, LoginBox: loginBox, IdPTokenBox: idpBox, ConsentBox: consentBox, Gate: g,
		UpstreamName: cfg.ResourceName, ScopeText: cfg.ScopeDescription, OperatorName: cfg.OperatorName,
		SecureCookies: cfg.PublicURL.Scheme == "https", Log: log,
		Audit: o.Audit, Limiter: ratelimit.New(cfg.OAuthRateLimits, maxRateLimitKeys, time.Now, o.Metrics.RateLimited),
		ObserveIdP:   func(op, outcome string, d time.Duration) { o.Metrics.IdP(idpName, op, outcome, d) },
		RefreshGrace: broker.DefaultRefreshGrace})
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
		log.Warn("consent page uses generic wording", "setting", "MCP_AUTHPROXY_SCOPE_DESCRIPTION",
			"reason", "set it to say in plain words what the "+cfg.Scope+" scope lets an app do (ADR-0010 §4)")
	}
	log.Info("broker ready", "reason", "keys "+fmt.Sprint(len(ring.KeyIDs()))+", signing with "+ring.SigningKeyID()+"; store in memory until slice 1.3")
	return &auth{register: b.Register, validator: v, checks: readiness(ring, st), background: func(ctx context.Context) { deny.Run(ctx, log) }}, nil
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

// readiness is what /readyz checks in authenticated mode: a signing key, and the store when it can
// be pinged (the in-memory store always can serve). Never the IdP (ADR-0021 §10).
func readiness(ring *token.KeyRing, st store.Store) []health.Check {
	checks := []health.Check{{Name: "keys", Ready: func(context.Context) error {
		if ring.SigningKeyID() == "" {
			return errors.New("no signing key")
		}
		return nil
	}}}
	storeReady := func(context.Context) error { return nil }
	if p, ok := st.(pinger); ok {
		storeReady = p.Ping
	}
	return append(checks, health.Check{Name: "store", Ready: storeReady})
}

// newBroker is broker.New; tests replace it to see the wired configuration.
var newBroker = broker.New

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
