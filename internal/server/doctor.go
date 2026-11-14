package server

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/envproxy"
	"github.com/byward-dev/byward/internal/store/postgres"
	"github.com/byward-dev/byward/internal/store/sqlite"
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
// clients, validates the IdP and gate settings, checks the store without opening or creating it, and
// checks the TLS certificate as startup does.
// The error is a configuration error; the warnings are what the proxy would log at startup.
func CheckOffline(cfg *config.Config) ([]Warning, error) {
	if err := checkUpstream(cfg); err != nil {
		return nil, err
	}
	if cfg.NoAuth {
		if err := errors.Join(looseSecretFiles(cfg)...); err != nil {
			return nil, err
		}
		pair, err := servableCert(cfg, time.Now())
		if err != nil {
			return nil, err
		}
		tlsWarnings := servingCertWarnings(cfg, pair, time.Now())
		return append(append(append([]Warning{{Message: "authentication is off (BYWARD_INSECURE_NO_AUTH); only the settings, the secret files, the TLS certificate and the upstream were checked"}}, tlsWarnings...), offlineHop(cfg)...), redundantStrips(cfg)...), nil
	}
	parts, err := loadAuthParts(cfg, nil)
	if err != nil {
		return nil, err
	}
	if err := parts.idp.refusal(time.Now()); err != nil {
		return nil, err
	}
	storeWarnings, err := checkStore(cfg)
	if err != nil {
		return nil, err
	}
	pair, err := servableCert(cfg, time.Now())
	if err != nil {
		return nil, err
	}
	tlsWarnings := servingCertWarnings(cfg, pair, time.Now())
	return append(append(append(append(append(parts.warnings, storeWarnings...), parts.idp.timedWarnings(time.Now())...), tlsWarnings...), offlineHop(cfg)...), redundantStrips(cfg)...), nil
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

// checkStore checks the configured store without opening it: the PostgreSQL DSN as Open would
// parse it, with what several replicas need, or the SQLite paths. Its errors name the settings,
// as openStore's do.
func checkStore(cfg *config.Config) ([]Warning, error) {
	if cfg.StorePostgresDSN == "" {
		if err := sqlite.CheckPaths(sqlite.Options{Dir: cfg.StoreDir, CounterFile: cfg.StoreCounterFile}); err != nil {
			return nil, fmt.Errorf("BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: %w (see docs/how-to/state.md)", err)
		}
		return nil, nil
	}
	if err := postgres.CheckDSN(cfg.StorePostgresDSN, cfg.Dev); err != nil {
		return nil, fmt.Errorf("BYWARD_STORE_POSTGRES_DSN_FILE: %w (see docs/how-to/postgres.md)", err)
	}
	return []Warning{replicaKeys}, nil
}

// replicaKeys is what the PostgreSQL store implies for every replica (ADR-0007 §5 and its #227
// amendment): the keys are not in the store, so each replica needs the same ones.
var replicaKeys = Warning{Setting: "BYWARD_STORE_POSTGRES_DSN_FILE",
	Message: "the PostgreSQL store serves several replicas, and keys never live in the store: a token sealed or an assertion signed by one replica is refused by another without the same keys; the per-address rate limits apply per replica",
	Fix:     "give every replica the same BYWARD_KEYS_DIR and BYWARD_ASSERTION_KEYS_DIR contents (docs/how-to/postgres.md)"}

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
	// UpstreamProxy is the HTTP proxy the relay would use for a request; nil is envproxy.Proxy, as the relay's.
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
		o.UpstreamProxy = envproxy.Proxy
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
		pair, err := diskCert(cfg)
		if err != nil {
			return r, err
		}
		r.Checks = append(r.Checks, servingCertChecks(cfg, pair, o.Now())...)
		for _, w := range redundantStrips(cfg) {
			r.Checks = append(r.Checks, doctor.CheckConfiguration.Result(doctor.Warn, w.Message, warningFix(w)))
		}
		r.Checks = append(r.Checks, upstreamResult(cfg, o.UpstreamProxy), doctor.TrustStore(trustSettings(), os.ReadFile, doctor.CertDirEntries))
		r.Checks = append(r.Checks, upstreamHopResult(ctx, cfg, o.Resolve)...)
		r.Checks = append(r.Checks, doctor.CheckAuthentication.Result(doctor.Warn, "authentication is off (BYWARD_INSECURE_NO_AUTH): there is no discovery and no IdP to check", "configure an IdP and remove BYWARD_INSECURE_NO_AUTH before exposing the proxy"))
		return r, nil
	}
	parts, err := loadAuthParts(cfg, o.IdP)
	if err != nil {
		return r, err
	}
	storeWarnings, err := checkStore(cfg)
	if err != nil {
		return r, err
	}
	pair, err := diskCert(cfg)
	if err != nil {
		return r, err
	}
	r.Checks = append(r.Checks, servingCertChecks(cfg, pair, o.Now())...)
	r.Checks = append(r.Checks, upstreamResult(cfg, o.UpstreamProxy), doctor.TrustStore(trustSettings(), os.ReadFile, doctor.CertDirEntries))
	r.Checks = append(r.Checks, upstreamHopResult(ctx, cfg, o.Resolve)...)
	if cfg.IdentityHeaders && cfg.UpstreamCommand == nil {
		r.Checks = append(r.Checks, identityHeadersResult(ctx, cfg.UpstreamURL.Hostname(), o.Resolve))
	}
	for _, w := range append(append(parts.warnings, storeWarnings...), redundantStrips(cfg)...) {
		r.Checks = append(r.Checks, doctor.CheckConfiguration.Result(doctor.Warn, w.Message, warningFix(w)))
	}
	target := doctor.Target{Resource: cfg.PublicURL, Issuer: cfg.Issuer(), HostsSetting: config.Setting{Name: "allowed-hosts"}.Env()}
	if parts.assertionKeys != nil {
		target.AssertionKeyID = parts.assertionKeys.SigningKeyID()
	}
	r.Checks = append(r.Checks, doctor.SelfProbe(ctx, o.Proxy, target)...)
	r.Checks = append(r.Checks, parts.idp.diagnose(ctx, o.Now())...)
	return r, nil
}

// trustSettings are the settings Go reads its roots from, whether a platform verifier is in use or
// kept by GODEBUG x509sslcertoverrideplatform=0 (both settings then ignored), and the number of
// roots Go loaded.
func trustSettings() doctor.TrustSettings {
	platform := runtime.GOOS == "darwin" || runtime.GOOS == "windows" || runtime.GOOS == "ios"
	// Go 1.27's default replaces the platform verifier; x509sslcertoverrideplatform=0 keeps it.
	ignored := platform && godebugValue(os.Getenv("GODEBUG"), "x509sslcertoverrideplatform") == "0"
	s := doctor.TrustSettings{CertFile: os.Getenv("SSL_CERT_FILE"), CertDir: os.Getenv("SSL_CERT_DIR"), PlatformVerifier: platform && !ignored, SettingsIgnored: ignored}
	if pool, err := x509.SystemCertPool(); err == nil {
		s.RootCount = len(pool.Subjects()) //nolint:staticcheck // SA1019: the only count of the system pool, shown, never used to verify
	}
	return s
}

// godebugValue is the value GODEBUG gives key, as Go parses it (internal/godebug): the last
// key=value entry wins, an entry without = is skipped, and a #bisect pattern is not part of the value.
func godebugValue(godebug, key string) string {
	v := ""
	for _, kv := range strings.Split(godebug, ",") {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v, _, _ = strings.Cut(val, "#")
		}
	}
	return v
}

func warningFix(w Warning) string {
	if w.Setting == "" {
		return ""
	}
	return w.Setting + ": " + w.Fix
}
