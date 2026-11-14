package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/servingcert"
)

var (
	tlsCertEnv = config.Setting{Name: "tls-cert-file"}.Env()
	tlsKeyEnv  = config.Setting{Name: "tls-key-file"}.Env()
)

// tlsWarnBefore is how long before the serving certificate expires the operator is warned.
const tlsWarnBefore = 30 * 24 * time.Hour

func tlsFiles(cfg *config.Config) servingcert.Files {
	return servingcert.Files{Cert: cfg.TLSCertFile, Key: cfg.TLSKeyFile}
}

// tlsError names the settings of a pair the proxy cannot serve.
func tlsError(err error) error {
	return fmt.Errorf("%s / %s: %w (see docs/how-to/tls.md)", tlsCertEnv, tlsKeyEnv, err)
}

// servingTLS is the public listener's TLS (#183): nil for plain HTTP. It refuses a pair the proxy
// cannot serve, and logs the warnings for the pair it starts with and for each renewed one. Go's
// default cipher suites stand; TLS 1.2 is the minimum.
func servingTLS(cfg *config.Config, log *slog.Logger, now func() time.Time) (*tls.Config, error) {
	if cfg.TLSCertFile == "" {
		return nil, nil
	}
	warn := func(p *servingcert.Pair) {
		for _, w := range servingCertWarnings(cfg, p, now()) {
			w.log(log)
		}
	}
	r, err := servingcert.Load(tlsFiles(cfg), servingcert.Options{Now: now, Log: log, CheckKey: secretCheck(cfg), Served: warn})
	if err != nil {
		return nil, tlsError(err)
	}
	warn(r.Current())
	// Certificates stays empty, so every handshake asks GetCertificate, which reloads changed files.
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.GetCertificate}, nil
}

// diskCert is the pair in the TLS files now, which the next handshake would serve, whatever its
// validity: nil for plain HTTP. A pair that cannot be read is a configuration error.
func diskCert(cfg *config.Config) (*servingcert.Pair, error) {
	if cfg.TLSCertFile == "" {
		return nil, nil
	}
	p, err := servingcert.Read(tlsFiles(cfg))
	if err != nil {
		return nil, tlsError(err)
	}
	return p, nil
}

// servableCert is the pair check --offline judges as startup would, without serving it: nil for
// plain HTTP.
func servableCert(cfg *config.Config, now time.Time) (*servingcert.Pair, error) {
	p, err := diskCert(cfg)
	if p == nil || err != nil {
		return nil, err
	}
	if err := p.Validity(now); err != nil {
		return nil, tlsError(err)
	}
	return p, nil
}

// servingCertChecks are the checks of the serving certificate p (nil for plain HTTP) at now: the
// chain's first expiry and the names it covers. Doctor reports them; startup and check warn with
// those that warn.
func servingCertChecks(cfg *config.Config, p *servingcert.Pair, now time.Time) []doctor.Result {
	if p == nil {
		return nil
	}
	return []doctor.Result{servingCertExpiry(p, now), servingCertNames(cfg, p)}
}

// servingCertWarnings are the checks that warn, as startup warnings.
func servingCertWarnings(cfg *config.Config, p *servingcert.Pair, now time.Time) []Warning {
	var w []Warning
	for _, r := range servingCertChecks(cfg, p, now) {
		if r.Status == doctor.Warn {
			w = append(w, Warning{Message: r.Message, Setting: tlsCertEnv, Fix: r.Fix})
		}
	}
	return w
}

// servingCertExpiry is the "TLS certificate expiry" check: it names the chain's certificate that
// expires first.
func servingCertExpiry(p *servingcert.Pair, now time.Time) doctor.Result {
	r := doctor.Result{Class: doctor.ClassProxy, Name: "TLS certificate expiry"}
	name, notAfter := p.FirstExpiry()
	err := p.Validity(now)
	at, notYet := servingcert.ServableAt(err)
	switch left := notAfter.Sub(now); {
	case err != nil && notYet:
		r.Status, r.Message = doctor.Fail, "the TLS certificate files are not valid yet: "+err.Error()
		r.Fix = "a running proxy serves them from " + at.UTC().Format(time.RFC3339) + " on, and a restart before then fails; replace them if that date is wrong"
	case err != nil:
		r.Status, r.Message = doctor.Fail, "the TLS certificate files cannot be served: "+err.Error()
		r.Fix = "replace both files with a valid pair; a running proxy keeps serving its previous certificate, and a restart fails"
	case left <= tlsWarnBefore:
		r.Status, r.Message = doctor.Warn, fmt.Sprintf("%s expires on %s, %s", name, notAfter.UTC().Format(time.DateOnly), inDays(notAfter, now))
		r.Fix = "renew it before then; the proxy serves the renewed files from the next connection on (docs/how-to/tls.md)"
	default:
		r.Status = doctor.Pass
		r.Message = fmt.Sprintf("the TLS certificate is valid until %s, when %s expires", notAfter.UTC().Format(time.DateOnly), name)
	}
	return r
}

// inDays says how soon notAfter is from now: under a day, or in calendar days in UTC, the zone its
// date is given in, so the count agrees with the date.
func inDays(notAfter, now time.Time) string {
	if notAfter.Sub(now) < 24*time.Hour {
		return "in less than a day"
	}
	midnight := func(t time.Time) time.Time { return t.UTC().Truncate(24 * time.Hour) }
	if days := int(midnight(notAfter).Sub(midnight(now)) / (24 * time.Hour)); days != 1 {
		return fmt.Sprintf("in %d days", days)
	}
	return "in 1 day"
}

// servingCertNames is the "TLS certificate names" check: a warning when the certificate covers
// neither the public URL's host nor any allowed host. It is only a warning: an ingress may verify
// the proxy under an internal name, such as a Kubernetes service's.
func servingCertNames(cfg *config.Config, p *servingcert.Pair) doctor.Result {
	r := doctor.Result{Class: doctor.ClassProxy, Name: "TLS certificate names"}
	hosts := []string{cfg.PublicURL.Hostname()}
	for _, h := range cfg.AllowedHosts {
		hosts = append(hosts, config.Hostname(h))
	}
	for _, h := range hosts {
		if p.Covers(h) {
			r.Status, r.Message = doctor.Pass, "the TLS certificate covers "+h
			return r
		}
	}
	r.Status, r.Message = doctor.Warn, "the TLS certificate covers neither the public URL's host nor any BYWARD_ALLOWED_HOSTS entry"
	r.Fix = "fine if only an ingress connects and verifies the proxy under another name, such as its service name; otherwise issue it for " + cfg.PublicURL.Hostname()
	return r
}
