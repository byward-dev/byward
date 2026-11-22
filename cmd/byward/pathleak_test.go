package main

import (
	"os"
	"path/filepath"
	"slices"
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
	// breaks is the variable whose file the scenario makes unusable: env sets it to a path in the
	// canary directory, and says starts with it as the setting at fault (but for the data directory,
	// which breaks through the defaults inside it).
	breaks string
	// says are what the error line says, all on that one line: the setting at fault (with the one it
	// pairs with, for the TLS and store files) and the cause. The first starts the error.
	says []string
	// env returns the settings under test: breaks set to a path in dir that fails, and any companion it
	// needs set to one beside dir that works; a setting set to nothing is unset (#428).
	env func(t *testing.T, dir string) []string
	// commands are the commands that refuse it; nil or empty for refusingCommands.
	commands [][]string
}

// pathLeakScenarios are the leak test's scenarios; every path variable has at least one that breaks it
// (TestEveryPathVariableHasALeakScenario).
func pathLeakScenarios() []pathLeakScenario {
	// tlsPair writes the pair's file that breaks into the canary directory dir, and the other, which
	// works, beside it (workingBeside): the leak test's perturbations of dir then reach only the broken
	// half (#617).
	tlsPair := func(t *testing.T, dir, breaks string, b testcert.Bundle) []string {
		cert, key := workingBeside(dir, "tls.crt"), workingBeside(dir, "tls.key")
		switch breaks {
		case "BYWARD_TLS_CERT_FILE":
			cert = filepath.Join(dir, "tls.crt")
		case "BYWARD_TLS_KEY_FILE":
			key = filepath.Join(dir, "tls.key")
		default:
			t.Fatalf("tlsPair: %q is neither half of the TLS pair", breaks)
		}
		writeFile(t, cert, string(b.Cert), 0o600)
		writeFile(t, key, string(b.Key), 0o600)
		return []string{"BYWARD_TLS_CERT_FILE=" + cert, "BYWARD_TLS_KEY_FILE=" + key}
	}
	bundle := func(t *testing.T) testcert.Bundle {
		return testcert.Issue(t, testcert.Options{Hosts: []string{"m.example"}, Leaf: testcert.Valid(time.Now(), 90)})
	}
	return []pathLeakScenario{
		{"a missing sealing key directory", "BYWARD_KEYS_DIR", []string{"BYWARD_KEYS_DIR: token: key directory: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_KEYS_DIR=" + filepath.Join(dir, "keys")}
		}, nil},
		{"a sealing key other users can read", "BYWARD_KEYS_DIR", []string{`BYWARD_KEYS_DIR: token: key file "k1": secret file has mode 0644`}, func(t *testing.T, dir string) []string {
			keys := filepath.Join(dir, "keys")
			sealingkey.Write(t, keys, "k1")
			chmod(t, filepath.Join(keys, "k1"), 0o644)
			return []string{"BYWARD_KEYS_DIR=" + keys}
		}, nil},
		{"a world-writable sealing key directory", "BYWARD_KEYS_DIR", []string{"BYWARD_KEYS_DIR: token: key directory is world-writable"}, func(t *testing.T, dir string) []string {
			keys := filepath.Join(dir, "keys")
			sealingkey.Write(t, keys, "k1")
			chmod(t, keys, 0o707)
			return []string{"BYWARD_KEYS_DIR=" + keys}
		}, nil},
		{"a missing static clients file", "BYWARD_STATIC_CLIENTS_FILE", []string{"BYWARD_STATIC_CLIENTS_FILE: static clients: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_STATIC_CLIENTS_FILE=" + filepath.Join(dir, "clients.json")}
		}, nil},
		{"a malformed static clients file", "BYWARD_STATIC_CLIENTS_FILE", []string{"BYWARD_STATIC_CLIENTS_FILE: static clients: not valid JSON: unexpected end of input"}, func(t *testing.T, dir string) []string {
			return []string{"BYWARD_STATIC_CLIENTS_FILE=" + writeFile(t, filepath.Join(dir, "clients.json"), `{"clients":`, 0o600)}
		}, nil},
		{"a missing assertion key directory", "BYWARD_ASSERTION_KEYS_DIR", []string{"BYWARD_ASSERTION_KEYS_DIR: assertion key directory: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_ASSERTION_KEYS_DIR=" + filepath.Join(dir, "assertion-keys")}
		}, nil},
		{"a state directory that is a file", "BYWARD_STORE_DIR", []string{"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: the state directory is not a directory"}, func(t *testing.T, dir string) []string {
			return []string{"BYWARD_STORE_DIR=" + writeFile(t, filepath.Join(dir, "state"), "", 0o600)}
		}, nil},
		// Only opening the store finds it: check --offline and doctor do not write (sqlite.CheckPaths).
		{"a state directory byward cannot write to", "BYWARD_STORE_DIR", []string{"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: the state directory is not writable: permission denied"}, func(t *testing.T, dir string) []string {
			skipAsRoot(t)
			state := filepath.Join(dir, "state")
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}
			chmod(t, state, 0o500)
			t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // G302: so TempDir can remove it
			return []string{"BYWARD_STORE_DIR=" + state}
		}, [][]string{nil}},
		{"a corrupt store counter file", "BYWARD_STORE_COUNTER_FILE", []string{"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: the counter file is corrupt"}, func(t *testing.T, dir string) []string {
			return []string{"BYWARD_STORE_COUNTER_FILE=" + writeFile(t, filepath.Join(dir, "store-writes"), "not a number\n", 0o600)}
		}, nil},
		{"a store counter file byward cannot read", "BYWARD_STORE_COUNTER_FILE", []string{"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: counter file: permission denied"}, func(t *testing.T, dir string) []string {
			skipAsRoot(t)
			return []string{"BYWARD_STORE_COUNTER_FILE=" + writeFile(t, filepath.Join(dir, "store-writes"), "1\n", 0o000)}
		}, nil},
		{"a client secret file other users can read", "BYWARD_ENTRA_CLIENT_SECRET_FILE", []string{"BYWARD_ENTRA_CLIENT_SECRET_FILE: secret file has mode 0644"}, func(t *testing.T, dir string) []string {
			return []string{"BYWARD_ENTRA_CLIENT_SECRET_FILE=" + writeFile(t, filepath.Join(dir, "secret"), entraSecret, 0o644)}
		}, nil},
		{"a missing TLS certificate file", "BYWARD_TLS_CERT_FILE", []string{"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: the certificate file: no such file or directory"}, func(t *testing.T, dir string) []string {
			key := writeFile(t, workingBeside(dir, "tls.key"), string(bundle(t).Key), 0o600)
			return []string{"BYWARD_TLS_CERT_FILE=" + filepath.Join(dir, "missing.crt"), "BYWARD_TLS_KEY_FILE=" + key}
		}, nil},
		{"a TLS key of another certificate", "BYWARD_TLS_KEY_FILE", []string{"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: the certificate and key files: tls: private key does not match public key"}, func(t *testing.T, dir string) []string {
			good, other := bundle(t), bundle(t)
			return tlsPair(t, dir, "BYWARD_TLS_KEY_FILE", testcert.Bundle{Cert: good.Cert, Key: other.Key})
		}, nil},
		{"an encrypted TLS key", "BYWARD_TLS_KEY_FILE", []string{"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: the key file: the private key is encrypted"}, func(t *testing.T, dir string) []string {
			encrypted := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")
			return tlsPair(t, dir, "BYWARD_TLS_KEY_FILE", testcert.Bundle{Cert: bundle(t).Cert, Key: encrypted})
		}, nil},
		{"a TLS chain certificate that does not parse", "BYWARD_TLS_CERT_FILE", []string{"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: the certificate file: x509: "}, func(t *testing.T, dir string) []string {
			b := bundle(t)
			junk := "-----BEGIN CERTIFICATE-----\nanVuaw==\n-----END CERTIFICATE-----\n"
			return tlsPair(t, dir, "BYWARD_TLS_CERT_FILE", testcert.Bundle{Cert: append(b.Cert, junk...), Key: b.Key})
		}, nil},
		// Defaults resolve inside the data directory; the first one byward opens names its own setting.
		{"a missing data directory", "BYWARD_DATA_DIR", []string{"BYWARD_KEYS_DIR: token: key directory: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_DATA_DIR=" + filepath.Join(dir, "data"), "BYWARD_KEYS_DIR=", "BYWARD_STATIC_CLIENTS_FILE=",
				"BYWARD_ASSERTION_KEYS_DIR=", "BYWARD_STORE_DIR=", "BYWARD_STORE_COUNTER_FILE="}
		}, nil},
		{"a missing federated token file", "BYWARD_ENTRA_FEDERATED_TOKEN_FILE", []string{"BYWARD_ENTRA_FEDERATED_TOKEN_FILE: no such file or directory"}, func(_ *testing.T, dir string) []string {
			return []string{"BYWARD_ENTRA_FEDERATED_TOKEN_FILE=" + filepath.Join(dir, "token"), "BYWARD_ENTRA_CLIENT_SECRET_FILE="}
		}, nil},
		missingSecretFile("BYWARD_UPSTREAM_CREDENTIAL_FILE", "upstream-credential"),
		missingSecretFile("BYWARD_UPSTREAM_ENV_FILE", "upstream-env"),
		missingSecretFile("BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE", "entra-client-certificate"),
		missingSecretFile("BYWARD_OIDC_CLIENT_SECRET_FILE", "oidc-client-secret"),
		missingSecretFile("BYWARD_OIDC_CLIENT_KEY_FILE", "oidc-client-key"),
		missingSecretFile("BYWARD_STORE_POSTGRES_DSN_FILE", "store-postgres-dsn"),
	}
}

// missingSecretFile is the scenario of a secret whose file, given as env, is missing; setting is the
// secret's setting.
func missingSecretFile(env, setting string) pathLeakScenario {
	says := []string{env + ": want the path of a file holding the secret, such as /run/secrets/" + setting + "; got a value (", "not shown): it cannot be read: no such file or directory"}
	return pathLeakScenario{"a missing " + setting + " file", env, says, func(_ *testing.T, dir string) []string {
		return []string{env + "=" + filepath.Join(dir, setting)}
	}, nil}
}

// A file setting whose file cannot be used is named by its setting and cause, never its path, in
// every output of startup, check --offline and doctor (security invariant 2, #575): the path may be a
// secret pasted where it belongs. The one place a path may show is startup's listing of the
// configuration and of the paths in use (ADR-0007 §6), which #575 decided is no error.
func TestAFileThatCannotBeUsedIsNamedByItsSettingNeverItsPath(t *testing.T) {
	for _, tc := range pathLeakScenarios() {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.says) == 0 {
				t.Fatal("it says nothing")
			}
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
			if len(commands) == 0 { // an empty list would test nothing
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
					// The setting at fault starts the error, after reportConfigError's prefix.
					said = said || strings.HasPrefix(line, "byward: configuration error: "+tc.says[0]) && containsAll(line, tc.says)
				}
				if !said {
					t.Errorf("%v: no line says %q; stdout %q stderr %q", args, tc.says, stdout, stderr)
				}
			}
			// The refusal is about the file: with the canary directory unsearchable, or gone, what it says goes
			// away (a missing file turns to "permission denied", one it cannot use to "no such file"). A line
			// that stays in both refuses the value, where it points or what it is set with, before any file is
			// opened, and shows nothing of how a file that cannot be used is named. Root searches any directory.
			if os.Geteuid() != 0 {
				stillSays := func(how string) bool { // a path shown is a leak here too, whatever the cause
					_, stdout, stderr := runDone(commands[0], env...)
					says := false
					for _, line := range strings.Split(stdout+stderr, "\n") {
						if isListing(line) {
							continue
						}
						if strings.Contains(line, pathCanary) {
							t.Errorf("%v: with the canary directory %s, a line shows the path: %q", commands[0], how, line)
						}
						says = says || containsAll(line, tc.says)
					}
					return says
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: so TempDir can remove it, should a check stop the test
				chmod(t, dir, 0)
				saidUnsearchable := stillSays("unsearchable")
				chmod(t, dir, 0o700)
				if err := os.Rename(dir, dir+"-gone"); err != nil {
					t.Fatal(err)
				}
				saidGone := saidUnsearchable && stillSays("gone")
				if err := os.Rename(dir+"-gone", dir); err != nil { // back, for the cleanups env registered in it
					t.Fatal(err)
				}
				if saidGone {
					t.Errorf("%v: still says %q with the canary directory unsearchable and with it gone: the refusal is not about the file", commands[0], tc.says)
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

// Every path variable (each path setting's, and each secret's file) has a scenario in the leak test
// that breaks it (#587): a new one fails here until it has one. A scenario breaks the variable it
// declares in breaks: it sets it to a path in the canary directory, where the leak test looks for a
// path shown, and what it says starts with it as the setting at fault, before the first ": " (alone,
// or in the pair the TLS and store files are named by). So neither a variable set to a file that
// works in another scenario nor a line that merely mentions it counts. The data directory breaks only
// through the defaults inside it, so its scenario names the default that fails instead. A scenario
// that skips as root covers nothing then.
func TestEveryPathVariableHasALeakScenario(t *testing.T) {
	brokenThroughDefaults := []string{"BYWARD_DATA_DIR"}
	broken := map[string]bool{}
	for _, tc := range pathLeakScenarios() {
		t.Run(tc.name, func(t *testing.T) {
			// The canary directory as TestAFileThatCannotBeUsedIsNamedByItsSettingNeverItsPath makes it.
			dir := filepath.Join(t.TempDir(), pathCanary)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			value := "" // the last one wins, as in the leak test
			env := tc.env(t, dir)
			for _, kv := range env {
				if v, ok := strings.CutPrefix(kv, tc.breaks+"="); ok {
					value = v
				}
			}
			if tc.breaks == "" {
				t.Fatal("it declares no variable it breaks: set breaks")
			}
			if !inCanary(dir, value) || !strings.Contains(value, pathCanary) {
				t.Fatalf("it breaks %q but does not set it to a path in the canary directory, spelt with it (the leak test looks for %q in what is shown): %q", tc.breaks, pathCanary, value)
			}
			if len(tc.says) == 0 {
				t.Fatal("it says nothing")
			}
			atFault, _, found := strings.Cut(tc.says[0], ": ")
			if !found {
				t.Fatalf("what it says first, %q, names no setting at fault before a \": \"", tc.says[0])
			}
			named := strings.Split(atFault, " / ") // "BYWARD_X", or a pair "BYWARD_X / BYWARD_Y" as server's TLS and store errors name it
			if !slices.Contains(named, tc.breaks) && !slices.Contains(brokenThroughDefaults, tc.breaks) {
				t.Fatalf("it breaks %q but what it says, %q, is not about it: says must start with it as the setting at fault, before the first \": \"", tc.breaks, tc.says)
			}
			// Every path it sets is named with the canary, so a line that shows any of them is a leak the leak
			// test sees. Any other than breaks is a companion that works: a regular file beside dir, not in it
			// or reached through it (workingBeside). A file in dir, or a link into it, dangling or not, would
			// fail under the leak test's perturbations too and could stand in for a refusal that is not about
			// breaks' file, even as the other half of a pair the line names (#617).
			for _, kv := range env {
				name, v, _ := strings.Cut(kv, "=")
				switch {
				case v == "":
				case !strings.Contains(v, pathCanary):
					t.Fatalf("it sets %s to %q, not named with the canary: a line that shows it would be a leak the leak test misses", name, v)
				case name == tc.breaks:
				case inCanary(dir, v):
					t.Fatalf("it also sets %s to a path in the canary directory, %q: put it beside, so that only %s's file is perturbed", name, v, tc.breaks)
				case !regularBeside(dir, v):
					t.Fatalf("it sets %s to %q, not a regular file directly beside the canary directory, spelt clean (workingBeside): a path through it, by a link or \"..\", would be perturbed too", name, v)
				}
			}
			broken[tc.breaks] = true
		})
	}
	for _, name := range config.PathVariables() {
		if !broken[name] {
			t.Errorf("%s holds a path but no scenario in pathLeakScenarios breaks it (set breaks: %q in one whose says starts with it)", name, name)
		}
	}
}

// workingBeside is the path, beside the canary directory dir, of a companion file that works: out of
// reach of the leak test's perturbations of dir, yet named with the canary, so a line that shows its
// path is a leak the leak test sees too.
func workingBeside(dir, name string) string {
	return filepath.Join(filepath.Dir(dir), pathCanary+"-"+name)
}

// regularBeside reports whether path is a regular file, not a link, directly in dir's parent and spelt
// clean: out of reach of the leak test's perturbations of dir, which a ".." through dir would not be.
func regularBeside(dir, path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular() && path == filepath.Clean(path) && filepath.Dir(path) == filepath.Dir(dir)
}

// inCanary reports whether path is dir or under it: spelt under it (cleaned), or resolved into it
// through any symlink on the way, as far as path exists. Both count, for the leak test's perturbations
// of dir reach a path that goes through it either way.
func inCanary(dir, path string) bool {
	under := func(d, p string) bool { return p == d || strings.HasPrefix(p, d+string(filepath.Separator)) }
	resolve := func(p string) string {
		for q := p; ; q = filepath.Dir(q) { // raw first: EvalSymlinks takes ".." after a symlink as the kernel does
			if r, err := filepath.EvalSymlinks(q); err == nil {
				rest, _ := filepath.Rel(filepath.Clean(q), filepath.Clean(p))
				return filepath.Join(r, rest)
			}
			if q == filepath.Dir(q) {
				return filepath.Clean(p)
			}
		}
	}
	return under(filepath.Clean(dir), filepath.Clean(path)) || under(resolve(dir), resolve(path))
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

// inCanary counts a path as in the canary directory when it is spelt under it or resolves into it,
// and not when it only shares the directory's name as a prefix (#617).
func TestInCanaryFindsAPathUnderTheCanaryDirectoryHoweverItIsReached(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, pathCanary)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "sub"), 0o700))
	writeFile(t, filepath.Join(dir, "state"), "", 0o600)
	outside := writeFile(t, filepath.Join(parent, "outside"), "", 0o600)
	must(os.Symlink(dir, filepath.Join(parent, "to-dir")))
	must(os.Symlink(outside, filepath.Join(dir, "to-outside")))
	must(os.Symlink(filepath.Join(dir, "sub"), filepath.Join(parent, "to-sub")))
	for _, tc := range []struct {
		path string
		want bool
	}{
		{dir, true},
		{dir + "/", true},
		{filepath.Join(dir, "missing", "deep"), true},
		{filepath.Join(parent, "to-dir", "missing", "deep"), true}, // a missing tail through a symlink: resolved as far as it exists
		{parent + "/./" + pathCanary + "/state", true},
		{filepath.Join(parent, "to-dir"), true},
		{filepath.Join(parent, "to-dir", "state"), true},
		{filepath.Join(dir, "to-outside"), true},              // spelt under dir: perturbing dir reaches it
		{filepath.Join(parent, "to-sub") + "/../state", true}, // ".." taken after the symlink, inside dir
		{workingBeside(dir, "tls.key"), false},
		{dir + "-gone", false},
		{outside, false},
		{"", false},
	} {
		if got := inCanary(dir, tc.path); got != tc.want {
			t.Errorf("inCanary(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// regularBeside accepts a companion only as a regular file directly beside the canary directory,
// spelt clean, so that the leak test's perturbations of the directory cannot reach it (#617).
func TestRegularBesideAcceptsOnlyARegularFileDirectlyBesideTheCanaryDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, pathCanary)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(parent, "deeper"), 0o700))
	must(os.Mkdir(dir, 0o700))
	beside := writeFile(t, workingBeside(dir, "tls.key"), "", 0o600)
	inside := writeFile(t, filepath.Join(dir, "state"), "", 0o600)
	writeFile(t, filepath.Join(parent, "deeper", pathCanary+"-x"), "", 0o600)
	must(os.Symlink(inside, workingBeside(dir, "link")))
	must(os.Symlink(filepath.Join(dir, "gone"), workingBeside(dir, "dangling")))
	must(os.Symlink(beside, workingBeside(dir, "to-beside")))
	must(os.Symlink(dir, filepath.Join(parent, "to-dir")))
	must(os.Mkdir(workingBeside(dir, "dir"), 0o700))
	for _, tc := range []struct {
		name string
		path string
		want bool
	}{
		{"a regular file beside", beside, true},
		{"the same, spelt with ./", parent + "/./" + pathCanary + "-tls.key", false},
		{"the same, spelt through the directory with ..", dir + "/../" + pathCanary + "-tls.key", false},
		{"the same, spelt through a link to the directory with ..", filepath.Join(parent, "to-dir") + "/../" + pathCanary + "-tls.key", false},
		{"a link beside into the directory", workingBeside(dir, "link"), false},
		{"a dangling link beside into the directory", workingBeside(dir, "dangling"), false},
		{"a link beside to the file beside", workingBeside(dir, "to-beside"), false},
		{"a directory beside", workingBeside(dir, "dir"), false},
		{"a file in the directory", inside, false},
		{"a file one level deeper", filepath.Join(parent, "deeper", pathCanary+"-x"), false},
		{"a missing path beside", workingBeside(dir, "missing"), false},
	} {
		if got := regularBeside(dir, tc.path); got != tc.want {
			t.Errorf("%s: regularBeside(%q) = %v, want %v", tc.name, tc.path, got, tc.want)
		}
	}
}
