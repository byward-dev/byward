package config

import "path/filepath"

// tls reads the public listener's certificate and key files (#183): both or neither, absolute
// paths, and only under an https public URL, which is what clients use.
func (c *Config) tls(v *Values) []error {
	certEnv, keyEnv := Setting{Name: "tls-cert-file"}.Env(), Setting{Name: "tls-key-file"}.Env()
	c.TLSCertFile, c.TLSKeyFile = v.get("tls-cert-file"), v.get("tls-key-file")
	if c.TLSCertFile == "" && c.TLSKeyFile == "" {
		return nil
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return []error{errorf("%s and %s: set both or neither", certEnv, keyEnv)}
	}
	var errs []error
	for _, f := range []struct{ env, path string }{{certEnv, c.TLSCertFile}, {keyEnv, c.TLSKeyFile}} {
		if !filepath.IsAbs(f.path) {
			errs = append(errs, errorf("%s: want an absolute path, got %q", f.env, f.path))
		}
	}
	if c.PublicURL != nil && c.PublicURL.Scheme != "https" {
		errs = append(errs, errorf("%s: TLS on the listener needs an https BYWARD_PUBLIC_URL; clients use the public URL, so an http one would reach a listener that speaks only TLS", certEnv))
	}
	return errs
}
