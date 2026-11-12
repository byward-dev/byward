package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/envproxy"
	"github.com/byward-dev/byward/internal/store/sqlite"
	"github.com/byward-dev/byward/internal/upstream/relay"
)

var secretExpirySetting = config.Setting{Name: "entra-client-secret-expires-at"}.Env()

func secretExpiry(cfg *config.Config, now time.Time) doctor.Result {
	return doctor.SecretExpiry(secretExpirySetting, cfg.EntraClientSecretExpiresAt, now)
}

// expiryWarning is the startup warning for a client secret that expires within 30 days or has
// expired; doctor reports the same check as a result of its own.
func expiryWarning(cfg *config.Config, now time.Time) (Warning, bool) {
	r := secretExpiry(cfg, now)
	if r.Status != doctor.Warn && r.Status != doctor.Fail {
		return Warning{}, false
	}
	return Warning{Message: r.Message, Setting: secretExpirySetting, Fix: r.Fix}, true
}

// CheckOffline is `byward check --offline` (ADR-0020 §7): everything the proxy validates at
// startup that needs no network and writes nothing. It reads the sealing keys and the static
// clients, validates the IdP and gate settings, and checks the store paths without creating them.
// The error is a configuration error; the warnings are what the proxy would log at startup.
func CheckOffline(cfg *config.Config) ([]Warning, error) {
	if err := checkUpstream(cfg); err != nil {
		return nil, err
	}
	if cfg.NoAuth {
		if err := errors.Join(looseSecretFiles(cfg)...); err != nil {
			return nil, err
		}
		return append(append([]Warning{{Message: "authentication is off (BYWARD_INSECURE_NO_AUTH); only the settings, the secret files and the upstream were checked"}}, offlineHop(cfg)...), redundantStrips(cfg)...), nil
	}
	parts, err := loadAuthParts(cfg, nil)
	if err != nil {
		return nil, err
	}
	if err := parts.idp.refusal(time.Now()); err != nil {
		return nil, err
	}
	if err := checkStorePaths(cfg); err != nil {
		return nil, err
	}
	return append(append(append(parts.warnings, parts.idp.timedWarnings(time.Now())...), offlineHop(cfg)...), redundantStrips(cfg)...), nil
}

// offlineHop is the plain-http upstream warning without the network: only an upstream given as an
// address is judged.
func offlineHop(cfg *config.Config) []Warning {
	w, ok := plainHTTPUpstream(context.Background(), cfg, func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("offline") })
	if !ok {
		return nil
	}
	return []Warning{w}
}

// checkStorePaths is sqlite.CheckPaths with the settings named, as openStore names them.
func checkStorePaths(cfg *config.Config) error {
	if err := sqlite.CheckPaths(sqlite.Options{Dir: cfg.StoreDir, CounterFile: cfg.StoreCounterFile}); err != nil {
		return fmt.Errorf("BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: %w (see docs/how-to/state.md)", err)
	}
	return nil
}

// DoctorOptions are the HTTP clients doctor uses; nil means the default for each. Tests point
// them at fakes.
type DoctorOptions struct {
	// IdP reaches the IdP (Entra's endpoints are fixed; a fake is reached through a transport).
	IdP *http.Client
	// Proxy reaches the proxy at its public URL; redirects are reported, never followed.
	Proxy *http.Client
	Now   func() time.Time
	// Resolve looks up the upstream's host for the plain identity headers and upstream hop checks; nil is the
	// system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// UpstreamProxy is the HTTP proxy the relay would use for a request; nil is the relay's own.
	UpstreamProxy func(*http.Request) (*url.URL, error)
}

// lookupNetIP is the system resolver, for startup and doctor; the package's tests replace it.
var lookupNetIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// probeTimeout bounds one doctor request (the discovery budget in docs/quality-lenses.md).
const probeTimeout = 10 * time.Second

// Doctor is `byward doctor` (ADR-0021 §11): the offline checks, a self-probe of the running proxy
// at its public URL, and the IdP's checks. The error is a configuration error, before any check.
func Doctor(ctx context.Context, cfg *config.Config, o DoctorOptions) (doctor.Report, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Proxy == nil {
		// Through a proxy setting Go misread, an error says only envproxy.Cause, never the address.
		o.Proxy = &http.Client{Timeout: probeTimeout, Transport: envproxy.Redact(http.DefaultTransport.(*http.Transport).Clone())}
	}
	if o.Resolve == nil {
		o.Resolve = lookupNetIP
	}
	if o.UpstreamProxy == nil {
		o.UpstreamProxy = relay.Proxy
	}
	// Configuration errors first: they stop doctor before any check (exit code 2).
	var r doctor.Report
	if err := checkUpstream(cfg); err != nil {
		return r, err
	}
	if cfg.NoAuth {
		if err := errors.Join(looseSecretFiles(cfg)...); err != nil {
			return r, err
		}
		for _, w := range redundantStrips(cfg) {
			r.Checks = append(r.Checks, doctor.Result{Class: doctor.ClassProxy, Name: "configuration", Status: doctor.Warn, Message: w.Message, Fix: warningFix(w)})
		}
		r.Checks = append(r.Checks, upstreamResult(cfg, o.UpstreamProxy))
		r.Checks = append(r.Checks, upstreamHopResult(ctx, cfg, o.Resolve)...)
		r.Checks = append(r.Checks, doctor.Result{Class: doctor.ClassProxy, Name: "authentication", Status: doctor.Warn,
			Message: "authentication is off (BYWARD_INSECURE_NO_AUTH): there is no discovery and no IdP to check",
			Fix:     "configure an IdP and remove BYWARD_INSECURE_NO_AUTH before exposing the proxy"})
		return r, nil
	}
	parts, err := loadAuthParts(cfg, o.IdP)
	if err != nil {
		return r, err
	}
	if err := checkStorePaths(cfg); err != nil {
		return r, err
	}
	r.Checks = append(r.Checks, upstreamResult(cfg, o.UpstreamProxy))
	r.Checks = append(r.Checks, upstreamHopResult(ctx, cfg, o.Resolve)...)
	if cfg.IdentityHeaders && cfg.UpstreamCommand == nil {
		r.Checks = append(r.Checks, identityHeadersResult(ctx, cfg.UpstreamURL.Hostname(), o.Resolve))
	}
	for _, w := range append(parts.warnings, redundantStrips(cfg)...) {
		r.Checks = append(r.Checks, doctor.Result{Class: doctor.ClassProxy, Name: "configuration", Status: doctor.Warn, Message: w.Message, Fix: warningFix(w)})
	}
	target := doctor.Target{Resource: cfg.PublicURL, Issuer: cfg.Issuer(), HostsSetting: config.Setting{Name: "allowed-hosts"}.Env()}
	if parts.assertionKeys != nil {
		target.AssertionKeyID = parts.assertionKeys.SigningKeyID()
	}
	r.Checks = append(r.Checks, doctor.SelfProbe(ctx, o.Proxy, target)...)
	r.Checks = append(r.Checks, parts.idp.diagnose(ctx, o.Now())...)
	return r, nil
}

func warningFix(w Warning) string {
	if w.Setting == "" {
		return ""
	}
	return w.Setting + ": " + w.Fix
}
