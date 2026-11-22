package config

// tls reads the public listener's certificate and key files (#183): both or neither, absolute
// paths, and only under an https public URL, which is what clients use. Each refusal names the files
// as the operator gave them (#619).
func (c *Config) tls(v *Values) []error {
	c.TLSCertFile, c.TLSKeyFile = parseText(v.value("tls-cert-file")), parseText(v.value("tls-key-file"))
	if c.TLSCertFile == "" && c.TLSKeyFile == "" {
		return nil
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return []error{errorf("%s and %s: set both or neither", v.NameAsGiven("tls-cert-file"), v.NameAsGiven("tls-key-file"))}
	}
	var errs []error
	for _, f := range []struct{ setting, path string }{{"tls-cert-file", c.TLSCertFile}, {"tls-key-file", c.TLSKeyFile}} {
		if err := absolute(f.setting, f.path); err != nil {
			errs = append(errs, err)
		}
	}
	if c.PublicURL != nil && c.PublicURL.Scheme != "https" {
		errs = append(errs, errorf("%s: TLS on the listener needs an https BYWARD_PUBLIC_URL; clients use the public URL, so an http one would reach a listener that speaks only TLS", v.NameAsGiven("tls-cert-file")))
	}
	return errs
}
