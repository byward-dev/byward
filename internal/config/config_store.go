package config

// storeBackend selects the store (ADR-0007 §2, amended for #227): SQLite in the state directory,
// or PostgreSQL when BYWARD_STORE_POSTGRES_DSN_FILE names a connection string. A named file selects
// PostgreSQL even when it is empty, and an empty one is refused, never read as SQLite. PostgreSQL is
// for several replicas, so it cannot serve a stdio upstream, whose processes live on one replica
// (ADR-0007 §4); and a state directory or counter file set beside it would be ignored, so that is an
// error too.
func (c *Config) storeBackend(v *Values) []error {
	c.StorePostgresDSN = parseText(v.value("store-postgres-dsn"))
	if !v.given("store-postgres-dsn") {
		return nil
	}
	var errs []error
	if err := v.emptySecretFile("store-postgres-dsn"); err != nil { // never SQLite in its place
		errs = append(errs, err)
	}
	if v.byKey["store-dir"].Source != SourceDefault {
		errs = append(errs, errorf("%s and %s: give one store, PostgreSQL or a SQLite state directory, not both", spelled(v.byKey["store-postgres-dsn"]), spelled(v.byKey["store-dir"])))
	}
	if v.byKey["store-counter-file"].Source != SourceDefault {
		errs = append(errs, errorf("%s and %s: the counter file belongs to the SQLite store; the PostgreSQL store finds a restore from the database itself (docs/how-to/postgres.md)", spelled(v.byKey["store-postgres-dsn"]), spelled(v.byKey["store-counter-file"])))
	}
	if v.stdioUpstream() {
		errs = append(errs, errorf("%s: the PostgreSQL store is for several replicas, and a stdio upstream's processes live on one (ADR-0007 §4); use the SQLite store", spelled(v.byKey["store-postgres-dsn"])))
	}
	if c.Dev {
		c.Relaxations = append(c.Relaxations, "the PostgreSQL store accepts a connection without verify-full TLS")
	}
	return errs
}
