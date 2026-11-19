package pgtest

import (
	"os"
	"path/filepath"
	"testing"
)

// ClearEnv leaves pgx none of the host's PostgreSQL environment: every other PG* variable unset, the
// password and service files pointed at files that do not exist, and an empty home directory. The
// docker CLI keeps the host's config: the real ~/.docker, or a DOCKER_CONFIG the host set and did not
// leave empty.
func TestClearEnvLeavesPgxNoneOfTheHostsEnvironment(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory to stand for the host's")
	}
	for _, c := range []struct {
		name         string
		unset        bool   // the host does not set DOCKER_CONFIG
		dockerConfig string // what the host sets it to otherwise
		want         string
	}{
		{"DOCKER_CONFIG unset", true, "", filepath.Join(home, ".docker")},
		{"DOCKER_CONFIG set empty by the host", false, "", filepath.Join(home, ".docker")},
		{"DOCKER_CONFIG set by the host", false, "/opt/docker-config", "/opt/docker-config"},
	} {
		t.Run(c.name, func(t *testing.T) {
			host := map[string]string{"PGSSLMODE": "disable", "PGSERVICE": "svc", "PGSSLCERTMODE": "", "PGFUTURE": "x"}
			for name, value := range host {
				t.Setenv(name, value)
			}
			t.Setenv("DOCKER_CONFIG", c.dockerConfig)
			if c.unset {
				_ = os.Unsetenv("DOCKER_CONFIG")
			}
			ClearEnv(t)
			for name := range host {
				if v, ok := os.LookupEnv(name); ok {
					t.Errorf("%s is still set (%q)", name, v)
				}
			}
			for _, name := range []string{"PGPASSFILE", "PGSERVICEFILE"} {
				path := os.Getenv(name)
				if _, err := os.Stat(path); path == "" || !os.IsNotExist(err) { //nolint:gosec // G703: the path ClearEnv just set
					t.Errorf("%s=%q names a file that exists, or none (%v)", name, path, err)
				}
			}
			newHome := os.Getenv("HOME")
			if entries, err := os.ReadDir(newHome); err != nil || len(entries) != 0 || newHome == home {
				t.Errorf("HOME=%q is not a new empty directory (%d entries, %v)", newHome, len(entries), err)
			}
			if got := os.Getenv("DOCKER_CONFIG"); got != c.want {
				t.Errorf("DOCKER_CONFIG=%q, want %q", got, c.want)
			}
		})
	}
}
