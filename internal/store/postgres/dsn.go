package postgres

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// parseDSN parses the DSN as pgx does (PG* environment variables, a service file and ~/.pgpass
// included) and checks the parsed result, so none of them can weaken TLS.
//
// The error never quotes the DSN. pgx masks passwords in its own message only on a best-effort
// basis (pgconn/errors.go, ParseConfigError.Error, v5.12.0 L147-158), and the errors it wraps can
// quote the string (a URL parse error does): only a file error, which names a path, is kept.
func parseDSN(dsn string, allowPlaintext bool) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		msg := "postgres store: the DSN does not parse (it is not shown: it may hold a password)"
		if pathErr, ok := errors.AsType[*fs.PathError](err); ok {
			return nil, fmt.Errorf("%s: %w", msg, pathErr)
		}
		return nil, errors.New(msg)
	}
	if !allowPlaintext {
		if err := requireVerifyFull(&cfg.ConnConfig.Config); err != nil {
			return nil, err
		}
	}
	if cfg.ConnConfig.RuntimeParams["application_name"] == "" {
		cfg.ConnConfig.RuntimeParams["application_name"] = "byward"
	}
	return cfg, nil
}

// requireVerifyFull accepts only sslmode=verify-full, for the first host and every fallback. pgx
// v5.12.0 (pgconn/config.go, configTLS L904-1097, and its caller L600-618) turns each sslmode into
// TLS configs this way:
//
//   - disable: one nil config (plaintext);
//   - allow: nil, then a config with InsecureSkipVerify; prefer, the default: that config, then nil;
//   - require: InsecureSkipVerify, and with sslrootcert it acts as verify-ca;
//   - verify-ca: InsecureSkipVerify, with the chain checked in VerifyPeerCertificate but not the
//     host name;
//   - verify-full: InsecureSkipVerify false and ServerName set to the host, so Go checks both; with
//     no sslrootcert, RootCAs stays nil and the system roots apply; sslrootcert=system forces it;
//   - a Unix-socket host gets a nil config whatever the sslmode (L603).
//
// So a nil config or InsecureSkipVerify anywhere means something less than verify-full.
func requireVerifyFull(c *pgconn.Config) error {
	tlsConfigs := []*pgconn.FallbackConfig{{Host: c.Host, Port: c.Port, TLSConfig: c.TLSConfig}}
	tlsConfigs = append(tlsConfigs, c.Fallbacks...)
	for _, f := range tlsConfigs {
		if f.TLSConfig == nil || f.TLSConfig.InsecureSkipVerify {
			return errors.New("postgres store: the DSN must use sslmode=verify-full (plaintext, a Unix socket and the weaker sslmodes are refused outside development mode)")
		}
	}
	return nil
}
