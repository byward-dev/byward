package postgres

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestEverySchemaVersionHasAFixture(t *testing.T) {
	for v := 1; v <= schemaVersion(); v++ {
		if _, err := os.Stat(fixturePath(v)); err != nil {
			t.Errorf("schema v%d has no fixture %s: add one when releasing a schema version", v, fixturePath(v))
		}
	}
}

func fixturePath(v int) string { return filepath.Join("testdata", "schema", fmt.Sprintf("v%d.sql", v)) }
