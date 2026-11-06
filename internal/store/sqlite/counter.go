package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Restore detection (ADR-0007 §9). Every write increments meta.writes and mirrors it to the counter
// file before the commit; see Store.write.

func (s *Store) init(ctx context.Context) error {
	if err := migrate(ctx, s.db); err != nil {
		return err
	}
	mirror, haveMirror, err := readCounter(s.counterFile)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var writes int64
		if err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = 'writes'").Scan(&writes); err != nil {
			return err
		}
		s.counterMissing = !haveMirror && writes > 0
		if haveMirror && mirror > writes {
			s.restored = true
			if _, err := tx.ExecContext(ctx, "UPDATE meta SET value = value + 1 WHERE key = 'epoch'"); err != nil {
				return err
			}
		}
		// This transaction rewrites the mirror from the database's counter, so the restored copy is
		// accepted from now on and the next start is normal.
		return tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = 'epoch'").Scan(&s.epoch)
	})
}

// RestoreDetected reports whether Open found the database behind its counter mirror and bumped the
// epoch. The caller logs and audits it (ADR-0021 §3, "store restore").
func (s *Store) RestoreDetected() bool { return s.restored }

// CounterMissing reports whether Open found a database with writes but no counter file. That is a
// first start after the file was lost or moved, and it is also how a restore together with the
// counter file looks; the caller should log it.
func (s *Store) CounterMissing() bool { return s.counterMissing }

// Epoch is the current store epoch.
func (s *Store) Epoch() int64 { return s.epoch }

// readCounter returns the mirrored write counter, or false when there is no mirror yet.
func readCounter(path string) (int64, bool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator's counter file
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("sqlite store: counter file %s: %w", path, err)
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || v < 0 {
		return 0, false, fmt.Errorf("sqlite store: counter file %s is corrupt; remove it to accept the database as it is", path)
	}
	return v, true, nil
}

// writeCounter replaces the mirror atomically (temporary file, then rename).
func writeCounter(path string, v int64) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".counter-*")
	if err != nil {
		return fmt.Errorf("sqlite store: counter file: %w", err)
	}
	_, werr := tmp.WriteString(strconv.FormatInt(v, 10) + "\n")
	serr := tmp.Sync() // a power loss must not leave an empty file, which Open refuses
	cerr := tmp.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("sqlite store: counter file: %w", errors.Join(werr, serr, cerr))
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("sqlite store: counter file: %w", err)
	}
	return syncDir(filepath.Dir(path))
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the operator's counter directory
	if err != nil {
		return fmt.Errorf("sqlite store: counter directory: %w", err)
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil || cerr != nil {
		return fmt.Errorf("sqlite store: counter directory: %w", errors.Join(serr, cerr))
	}
	return nil
}
