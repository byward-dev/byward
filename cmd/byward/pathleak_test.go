package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/testutil/assertionkey"
	"github.com/byward-dev/byward/internal/testutil/sealingkey"
	"github.com/byward-dev/byward/internal/testutil/testcert"
)

// pathCanary marks the directory every path under test is in: a secret pasted where a path belongs
// would show the same way.
const pathCanary = "PATH575CANARY"

// The commands that refuse a file that cannot be used: startup, check --offline and doctor, text and
// --json.
var refusingCommands = [][]string{nil, {"check", "--offline"}, {"doctor"}, {"doctor", "--json"}}

// pathLeakScenario is a file setting set to a path in a canary directory that byward cannot use.
type pathLeakScenario struct {
	name string
	// says are what the error line says, all on that one line: the setting at fault and the cause.
	says []string
	// env returns the settings under test, set to paths in dir that fail; a setting set to nothing is
	// unset (#428).
	env func(t *testing.T, dir string) []string
	// commands are the commands that refuse it; nil for refusingCommands.
	commands [][]string
}

// pathLeakScenarios are the leak test's scenarios; every path setting has at least one
// (TestEveryPathSettingHasALeakScenario).
func pathLeakScenarios() []pathLeakScenario {
	tlsPair := func(t *testing.T, dir string, b testcert.Bundle) []string {
		cert, key := b.Write(t, dir)
		return []string{"BYWARD_TLS_CERT_FILE=" + cert, "BYWARD_TLS_KEY_FILE=" + key}
	}
	bundle := func(t *testing.T) testcert.Bundle {
		return testcert.Issue(t, testcert.Options{Hosts: []string{"m.example"}, Leaf: testcert.Valid(time.Now(), 90)})
	}
	return []pathLeakScenario{
		{"a missing sealing key directory", []string{"BYWARD_KEYS_DIR: token: key directory: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_KEYS_DIR=" + filepath.Join(dir, "keys")}
		}, nil},
		{"a sealing key other users can read", []string{`BYWARD_KEYS_DIR: token: key file "k1": secret file has mode 0644`}, func(t *testing.T, dir string) []string {
			keys := filepath.Join(dir, "keys")
			sealingkey.Write(t, keys, "k1")
			chmod(t, filepath.Join(keys, "k1"), 0o644)
			return []string{"BYWARD_KEYS_DIR=" + keys}
		}, nil},
		{"a world-writable sealing key directory", []string{"BYWARD_KEYS_DIR: token: key directory is world-writable"}, func(t *testing.T, dir string) []string {
			keys := filepath.Join(dir, "keys")
			sealingkey.Write(t, keys, "k1")
			chmod(t, keys, 0o707)
			return []string{"BYWARD_KEYS_DIR=" + keys}
		}, nil},
		{"a missing static clients file", []string{"BYWARD_STATIC_CLIENTS_FILE: static clients: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_STATIC_CLIENTS_FILE=" + filepath.Join(dir, "clients.json")}
		}, nil},
		{"a malformed static clients file", []string{"BYWARD_STATIC_CLIENTS_FILE: static clients: not valid JSON: unexpected end of input"}, func(t *testing.T, dir string) []string {
			return []string{"BYWARD_STATIC_CLIENTS_FILE=" + writeFile(t, filepath.Join(dir, "clients.json"), `{"clients":`, 0o600)}
		}, nil},
		{"a missing assertion key directory", []string{"BYWARD_ASSERTION_KEYS_DIR: assertion key directory: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_ASSERTION_KEYS_DIR=" + filepath.Join(dir, "assertion-keys")}
		}, nil},
		{"a state directory that is a file", []string{"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: the state directory is not a directory"}, func(t *testing.T, dir string) []string {
			return []string{"BYWARD_STORE_DIR=" + writeFile(t, filepath.Join(dir, "state"), "", 0o600)}
		}, nil},
		// Only opening the store finds it: check --offline and doctor do not write (sqlite.CheckPaths).
		{"a state directory byward cannot write to", []string{"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: the state directory is not writable: permission denied"}, func(t *testing.T, dir string) []string {
			skipAsRoot(t)
			state := filepath.Join(dir, "state")
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}
			chmod(t, state, 0o500)
			t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // G302: so TempDir can remove it
			return []string{"BYWARD_STORE_DIR=" + state}
		}, [][]string{nil}},
		{"a corrupt store counter file", []string{"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: the counter file is corrupt"}, func(t *testing.T, dir string) []string {
			return []string{"BYWARD_STORE_COUNTER_FILE=" + writeFile(t, filepath.Join(dir, "store-writes"), "not a number\n", 0o600)}
		}, nil},
		{"a store counter file byward cannot read", []string{"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: counter file: permission denied"}, func(t *testing.T, dir string) []string {
			skipAsRoot(t)
			return []string{"BYWARD_STORE_COUNTER_FILE=" + writeFile(t, filepath.Join(dir, "store-writes"), "1\n", 0o000)}
		}, nil},
		{"a client secret file other users can read", []string{"BYWARD_ENTRA_CLIENT_SECRET_FILE: secret file has mode 0644"}, func(t *testing.T, dir string) []string {
			return []string{"BYWARD_ENTRA_CLIENT_SECRET_FILE=" + writeFile(t, filepath.Join(dir, "secret"), entraSecret, 0o644)}
		}, nil},
		{"a missing TLS certificate file", []string{"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: the certificate file: no such file or directory"}, func(t *testing.T, dir string) []string {
			_, key := bundle(t).Write(t, dir)
			return []string{"BYWARD_TLS_CERT_FILE=" + filepath.Join(dir, "missing.crt"), "BYWARD_TLS_KEY_FILE=" + key}
		}, nil},
		{"a TLS key of another certificate", []string{"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: the certificate and key files: tls: private key does not match public key"}, func(t *testing.T, dir string) []string {
			good, other := bundle(t), bundle(t)
			return tlsPair(t, dir, testcert.Bundle{Cert: good.Cert, Key: other.Key})
		}, nil},
		{"an encrypted TLS key", []string{"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: the key file: the private key is encrypted"}, func(t *testing.T, dir string) []string {
			encrypted := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")
			return tlsPair(t, dir, testcert.Bundle{Cert: bundle(t).Cert, Key: encrypted})
		}, nil},
		{"a TLS chain certificate that does not parse", []string{"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: the certificate file: x509: "}, func(t *testing.T, dir string) []string {
			b := bundle(t)
			junk := "-----BEGIN CERTIFICATE-----\nanVuaw==\n-----END CERTIFICATE-----\n"
			return tlsPair(t, dir, testcert.Bundle{Cert: append(b.Cert, junk...), Key: b.Key})
		}, nil},
		// Defaults resolve inside the data directory; the first one byward opens names its own setting.
		{"a missing data directory", []string{"BYWARD_KEYS_DIR: token: key directory: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_DATA_DIR=" + filepath.Join(dir, "data"), "BYWARD_KEYS_DIR=", "BYWARD_STATIC_CLIENTS_FILE=",
				"BYWARD_ASSERTION_KEYS_DIR=", "BYWARD_STORE_DIR=", "BYWARD_STORE_COUNTER_FILE="}
		}, nil},
		{"a missing federated token file", []string{"BYWARD_ENTRA_FEDERATED_TOKEN_FILE: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_ENTRA_FEDERATED_TOKEN_FILE=" + filepath.Join(dir, "token"), "BYWARD_ENTRA_CLIENT_SECRET_FILE="}
		}, nil},
		{"a missing upstream-credential file", []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE: want the path of a file holding the secret, such as /run/secrets/upstream-credential; got a value (", "not shown): it cannot be read: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + filepath.Join(dir, "upstream-credential")}
		}, nil},
		{"a missing upstream-env file", []string{"BYWARD_UPSTREAM_ENV_FILE: want the path of a file holding the secret, such as /run/secrets/upstream-env; got a value (", "not shown): it cannot be read: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_UPSTREAM_ENV_FILE=" + filepath.Join(dir, "upstream-env")}
		}, nil},
		{"a missing entra-client-certificate file", []string{"BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: want the path of a file holding the secret, such as /run/secrets/entra-client-certificate; got a value (", "not shown): it cannot be read: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE=" + filepath.Join(dir, "entra-client-certificate")}
		}, nil},
		{"a missing oidc-client-secret file", []string{"BYWARD_OIDC_CLIENT_SECRET_FILE: want the path of a file holding the secret, such as /run/secrets/oidc-client-secret; got a value (", "not shown): it cannot be read: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_OIDC_CLIENT_SECRET_FILE=" + filepath.Join(dir, "oidc-client-secret")}
		}, nil},
		{"a missing oidc-client-key file", []string{"BYWARD_OIDC_CLIENT_KEY_FILE: want the path of a file holding the secret, such as /run/secrets/oidc-client-key; got a value (", "not shown): it cannot be read: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_OIDC_CLIENT_KEY_FILE=" + filepath.Join(dir, "oidc-client-key")}
		}, nil},
		{"a missing store-postgres-dsn file", []string{"BYWARD_STORE_POSTGRES_DSN_FILE: want the path of a file holding the secret, such as /run/secrets/store-postgres-dsn; got a value (", "not shown): it cannot be read: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + filepath.Join(dir, "store-postgres-dsn")}
		}, nil},
	}
}

// A file setting whose file cannot be used is named by its setting and cause, never its path, in
// every output of startup, check --offline and doctor (security invariant 2, #575): the path may be a
// secret pasted where it belongs. The one place a path may show is startup's listing of the
// configuration and of the paths in use (ADR-0007 §6), which #575 decided is no error.
func TestAFileThatCannotBeUsedIsNamedByItsSettingNeverItsPath(t *testing.T) {
	for _, tc := range pathLeakScenarios() {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), pathCanary)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			env := append(authEnv(t), serveEnv("https://m.example/mcp", "127.0.0.1:0")...)
			for _, kv := range tc.env(t, dir) {
				name, _, _ := strings.Cut(kv, "=")
				env = append(without(env, name+"="), kv)
			}
			commands := tc.commands
			if commands == nil {
				commands = refusingCommands
			}
			for _, args := range commands {
				code, stdout, stderr := runDone(args, env...) // a startup that wrongly succeeds stops at once
				if code == exitOK {
					t.Fatalf("%v: exit 0, want the file refused; stderr %q", args, stderr)
				}
				said := false
				for _, line := range strings.Split(stdout+stderr, "\n") {
					if isListing(line) {
						continue
					}
					if strings.Contains(line, pathCanary) {
						t.Errorf("%v: a line shows the path: %q", args, line)
					}
					said = said || containsAll(line, tc.says)
				}
				if !said {
					t.Errorf("%v: no line says %q; stdout %q stderr %q", args, tc.says, stdout, stderr)
				}
			}
		})
	}
}

// A key file whose name holds a newline cannot forge a line of byward's output (#505, #575): an
// error names a key file by its quoted name.
func TestAKeyFileNamedWithANewlineCannotForgeALine(t *testing.T) {
	const forged = "byward: configuration error: forged"
	for _, tc := range []struct {
		setting string
		dir     func(t *testing.T) string
	}{
		{"BYWARD_KEYS_DIR", func(t *testing.T) string {
			keys := sealingkey.Dir(t)
			sealingkey.Write(t, keys, "k2\n"+forged) // not a key ID: refused, by its quoted name
			return keys
		}},
		{"BYWARD_ASSERTION_KEYS_DIR", func(t *testing.T) string {
			keys := assertionkey.Dir(t)
			assertionkey.Write(t, keys, "k2\n"+forged, false) // not a key ID: refused, by its quoted name
			return keys
		}},
	} {
		t.Run(tc.setting, func(t *testing.T) {
			env := append(authEnv(t), serveEnv("https://m.example/mcp", "127.0.0.1:0")...)
			env = append(without(env, tc.setting+"="), tc.setting+"="+tc.dir(t))
			for _, args := range refusingCommands {
				code, stdout, stderr := runDone(args, env...) // a startup that wrongly succeeds stops at once
				if code == exitOK {
					t.Fatalf("%v: exit 0, want the key file refused", args)
				}
				for _, line := range strings.Split(stdout+stderr, "\n") {
					if strings.HasPrefix(line, forged) {
						t.Fatalf("%v: the key file's name forged a line: %q", args, line)
					}
				}
				if !strings.Contains(stdout+stderr, `k2\n`+forged) {
					t.Errorf("%v: the key file is not named by its quoted name; stdout %q stderr %q", args, stdout, stderr)
				}
			}
		})
	}
}

// Every path setting, and every secret's file, has a scenario in the leak test (#587): a new one
// fails here until it has one.
func TestEveryPathSettingHasALeakScenario(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range pathLeakScenarios() {
		t.Run(tc.name, func(t *testing.T) {
			for _, kv := range tc.env(t, t.TempDir()) {
				if name, value, _ := strings.Cut(kv, "="); value != "" {
					covered[name] = true
				}
			}
		})
	}
	settings := config.PathSettings()
	if len(settings) == 0 {
		t.Fatal("config lists no path settings")
	}
	for _, name := range settings {
		if !covered[name] {
			t.Errorf("%s holds a path but no scenario in pathLeakScenarios sets it", name)
		}
	}
}

// containsAll reports whether line holds every one of parts.
func containsAll(line string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(line, p) {
			return false
		}
	}
	return true
}

// isListing reports whether line is in startup's listing: a setting's value as configured
// (`config`), or a path in use, defaults resolved (`path`, logPaths). The listing shows every path,
// so a file that cannot be used shows there; #575 decided that is no error.
func isListing(line string) bool {
	return strings.Contains(line, `"msg":"config"`) || strings.Contains(line, `"level":"INFO","msg":"path","setting":"BYWARD_`)
}

// skipAsRoot skips a row whose file mode root would ignore.
func skipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads and writes any file")
	}
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	chmod(t, path, mode) // WriteFile's mode passes through the umask
	return path
}
