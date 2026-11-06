package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/broker"
	"github.com/corker/mcp-authproxy/internal/config"
	"github.com/corker/mcp-authproxy/internal/health"
	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/idp/entra"
	"github.com/corker/mcp-authproxy/internal/registration"
	"github.com/corker/mcp-authproxy/internal/resource"
	"github.com/corker/mcp-authproxy/internal/store/memory"
	"github.com/corker/mcp-authproxy/internal/token"
)

// maxJTIs bounds the in-memory private_key_jwt replay cache.
const maxJTIs = 10000

// auth is what authenticated mode adds: the broker's routes, the access-token validator and the
// readiness checks for its keys and store.
type auth struct {
	register  func(*http.ServeMux)
	validator resource.Validator
	checks    []health.Check
}

// pinger is a store that can say whether it is reachable; the in-memory store has nothing to check.
type pinger interface{ Ping(context.Context) error }

// buildAuth wires the broker (slice 1.2): sealing keys, Entra, static clients and the in-memory
// store (SQLite arrives with slice 1.3). Errors name the file or setting at fault.
func buildAuth(cfg *config.Config, log *slog.Logger, o Observability) (*auth, error) {
	ring, err := token.LoadKeyRing(cfg.KeysDir)
	if err != nil {
		return nil, fmt.Errorf("MCP_AUTHPROXY_KEYS_DIR: %w", err)
	}
	for _, id := range ring.KeyIDs() {
		use := "verification"
		if id == ring.SigningKeyID() {
			use = "signing"
		}
		o.Audit.Record(nil, audit.Event{Name: audit.KeyLoaded, Outcome: audit.Success, Reason: use, KeyID: id})
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
	clients, err := registration.LoadStatic(cfg.StaticClientsFile, os.ReadFile, registration.NewMemoryJTICache(time.Now, maxJTIs))
	if err != nil {
		return nil, fmt.Errorf("MCP_AUTHPROXY_STATIC_CLIENTS_FILE: %w", err)
	}
	if lister, ok := clients.(interface{ IDs() []string }); ok {
		for _, id := range lister.IDs() {
			o.Audit.Record(nil, audit.Event{Name: audit.ClientRegistered, Outcome: audit.Success, Reason: "static", ClientID: id})
		}
	}
	provider, err := entra.New(entra.Config{Tenant: cfg.EntraTenant, ClientID: cfg.EntraClientID,
		ClientAuth: idp.ClientSecret(cfg.EntraClientSecret), RedirectURL: cfg.Issuer() + "/callback/entra"})
	if err != nil {
		return nil, fmt.Errorf("entra settings (MCP_AUTHPROXY_ENTRA_*): %w", err)
	}
	st := memory.New()
	b, err := broker.New(broker.Config{Issuer: cfg.Issuer(), Resource: cfg.PublicURL, Scope: cfg.Scope, IdPName: "entra",
		IdPLabel: "Microsoft Entra", IdP: provider, Clients: clients, Store: st, Sealer: sealer,
		LoginBox: loginBox, IdPTokenBox: idpBox, SecureCookies: cfg.PublicURL.Scheme == "https", Log: log,
		Audit: o.Audit, ObserveIdP: func(op, outcome string, d time.Duration) { o.Metrics.IdP("entra", op, outcome, d) }})
	if err != nil {
		return nil, err
	}
	v, err := token.NewValidator(sealer, b.Deny(), nil)
	if err != nil {
		return nil, err
	}
	log.Info("broker ready", "reason", "keys "+fmt.Sprint(len(ring.KeyIDs()))+", signing with "+ring.SigningKeyID()+"; store in memory until slice 1.3")
	checks := []health.Check{{Name: "keys", Ready: func(context.Context) error {
		if ring.SigningKeyID() == "" {
			return errors.New("no signing key")
		}
		return nil
	}}}
	if p, ok := any(st).(pinger); ok {
		checks = append(checks, health.Check{Name: "store", Ready: p.Ping})
	} else {
		checks = append(checks, health.Check{Name: "store", Ready: func(context.Context) error { return nil }})
	}
	return &auth{register: b.Register, validator: v, checks: checks}, nil
}
