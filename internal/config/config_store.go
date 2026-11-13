package config

// storeBackend selects the store (ADR-0007 §2, amended for #227): SQLite in the state directory,
// or PostgreSQL when BYWARD_STORE_POSTGRES_DSN_FILE names a connection string. PostgreSQL is for
// several replicas, so it cannot serve a stdio upstream, whose processes live on one replica
// (ADR-0007 §4); and a state directory set beside it would be ignored, so that is an error too.
func (c *Config) storeBackend(v *Values) []error {
	c.StorePostgresDSN = v.get("store-postgres-dsn")
	if c.StorePostgresDSN == "" {
		return nil
	}
	var errs []error
	if v.byKey["store-dir"].Source != SourceDefault {
		errs = append(errs, errorf("BYWARD_STORE_POSTGRES_DSN_FILE and BYWARD_STORE_DIR: give one store, PostgreSQL or a SQLite state directory, not both"))
	}
	if c.UpstreamCommand != nil {
		errs = append(errs, errorf("BYWARD_STORE_POSTGRES_DSN_FILE: the PostgreSQL store is for several replicas, and a stdio upstream's processes live on one (ADR-0007 §4); use the SQLite store"))
	}
	if c.Dev {
		c.Relaxations = append(c.Relaxations, "the PostgreSQL store accepts a connection without verify-full TLS")
	}
	return errs
}
