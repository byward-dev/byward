// Package config loads the proxy's settings from flags, `BYWARD_*` environment variables
// and defaults, from one registry that also drives validation and redaction (ADR-0020).
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// EnvPrefix starts every environment variable the proxy reads.
const envPrefix = "BYWARD_"

// Setting is one registry entry. Every setting has a flag and an env name.
type Setting struct {
	Name    string // flag name, kebab-case; the env name is derived from it
	Group   Group  // the section of the settings reference it is listed in
	Default string
	Help    string
	Secret  bool // read only from a file: `<ENV>_FILE` or `--<name>-file`
	Bool    bool
	// Auth marks settings that configure authentication (IdP, broker); --insecure-no-auth refuses
	// to start when any of them is set, so a half-configured production setup never runs open.
	Auth bool
}

// Env is the setting's environment variable name.
func (s Setting) Env() string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(s.Name, "-", "_"))
}

// Source tells where a value came from.
type Source string

// Sources, in precedence order (highest first).
const (
	SourceFlag    Source = "flag"
	SourceEnv     Source = "env"
	SourceFile    Source = "file"
	SourceDefault Source = "default"
)

// Value is a resolved setting.
type Value struct {
	Setting Setting
	Raw     string
	Source  Source
	Path    string // the file a SourceFile secret was read from
	From    string // how that file was named: the flag or the env variable, for error messages
}

// SecretFile is a file a secret was read from, and the flag or env variable that named it.
type SecretFile struct{ From, Path string }

// SecretFiles lists the files secrets were read from, in registry order; the server checks their
// permissions (ADR-0018 §11).
func (v *Values) SecretFiles() []SecretFile {
	var out []SecretFile
	for _, n := range v.order {
		if val := v.byKey[n]; val.Source == SourceFile {
			out = append(out, SecretFile{From: val.From, Path: val.Path})
		}
	}
	return out
}

// Display is the value as it may be logged: secrets are always redacted.
func (v Value) Display() string {
	if v.Setting.Secret && v.Raw != "" {
		return "<redacted>"
	}
	return v.Raw
}

// configError is a configuration error; the process exits with its own code for these.
type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

func errorf(format string, a ...any) error { return &configError{msg: fmt.Sprintf(format, a...)} }

// Values holds the resolved registry.
type Values struct {
	order []string
	byKey map[string]Value
	// command is the stdio upstream's argv given after --; its Value shows it for display only.
	command []string
}

// get returns the raw value of a setting.
func (v *Values) get(name string) string { return v.byKey[name].Raw }

// Effective lists every setting with its source, in registry order.
func (v *Values) Effective() []Value {
	out := make([]Value, 0, len(v.order))
	for _, n := range v.order {
		out = append(out, v.byKey[n])
	}
	return out
}

// commandSetting is the setting a command after -- fills, as a JSON array.
const commandSetting = "upstream-command"

// readFileFunc reads a secret file; main passes os.ReadFile.
type readFileFunc = func(path string) ([]byte, error)

// resolve applies flags > env > defaults over a registry. extraFlags registers command-line-only
// flags (actions such as --version) on the same flag set. Inline secrets are rejected unless
// allowInlineSecrets is set (development mode).
func resolve(reg []Setting, args, environ []string, readFile readFileFunc, extraFlags func(*flag.FlagSet)) (*Values, error) {
	fs := flag.NewFlagSet("byward", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	flagVals := map[string]*string{}
	fileFlagVals := map[string]*string{}
	for _, s := range reg {
		if s.Bool {
			flagVals[s.Name] = new(string)
			fs.Var((*boolValue)(flagVals[s.Name]), s.Name, s.Help)
			continue
		}
		if s.Secret {
			fileFlagVals[s.Name] = fs.String(s.Name+"-file", "", "file holding "+s.Help)
			continue
		}
		flagVals[s.Name] = fs.String(s.Name, "", s.Help)
	}
	if extraFlags != nil {
		extraFlags(fs)
	}
	// Everything after the first -- is the stdio upstream's command (ADR-0019 §8).
	var command []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, command = args[:i], args[i+1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, errorf("%v", err)
	}
	if fs.NArg() > 0 {
		return nil, errorf("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	env := map[string]string{}
	for _, kv := range environ {
		k, val, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(k, envPrefix) {
			env[k] = val
		}
	}
	if err := checkUnknownEnv(reg, env); err != nil {
		return nil, err
	}

	vals := &Values{byKey: map[string]Value{}}
	for _, s := range reg {
		v := Value{Setting: s, Raw: s.Default, Source: SourceDefault}
		switch {
		case s.Secret && set[s.Name+"-file"]:
			raw, err := readSecret(readFile, *fileFlagVals[s.Name], "--"+s.Name+"-file")
			if err != nil {
				return nil, err
			}
			v.Raw, v.Source, v.Path, v.From = raw, SourceFile, *fileFlagVals[s.Name], "--"+s.Name+"-file"
		case !s.Secret && set[s.Name]:
			v.Raw, v.Source = *flagVals[s.Name], SourceFlag
		case s.Secret && env[s.Env()+"_FILE"] != "":
			raw, err := readSecret(readFile, env[s.Env()+"_FILE"], s.Env()+"_FILE")
			if err != nil {
				return nil, err
			}
			v.Raw, v.Source, v.Path, v.From = raw, SourceFile, env[s.Env()+"_FILE"], s.Env()+"_FILE"
		default:
			if e, ok := env[s.Env()]; ok {
				v.Raw, v.Source = e, SourceEnv
			}
		}
		vals.order = append(vals.order, s.Name)
		vals.byKey[s.Name] = v
	}
	if command != nil {
		v, ok := vals.byKey[commandSetting]
		if !ok || v.Source != SourceDefault {
			return nil, errorf("give the stdio upstream command either after -- or with --%s / %s, not both", commandSetting, v.Setting.Env())
		}
		if len(command) == 0 {
			return nil, errorf("no command after --")
		}
		// Kept as argv, not re-encoded: shown quoted, word by word.
		quoted := make([]string, len(command))
		for i, a := range command {
			quoted[i] = strconv.Quote(a)
		}
		v.Raw, v.Source = strings.Join(quoted, " "), SourceFlag
		vals.byKey[commandSetting] = v
		vals.command = command
	}
	return vals, nil
}

// inlineSecrets lists secret settings given directly in env instead of through a file.
func (v *Values) inlineSecrets() []string {
	var out []string
	for _, val := range v.Effective() {
		if val.Setting.Secret && val.Source == SourceEnv {
			out = append(out, val.Setting.Env())
		}
	}
	return out
}

// boolValue is a boolean flag (`--dev`, `--dev=false`) kept as a string for validation.
type boolValue string

func (b *boolValue) String() string     { return string(*b) }
func (b *boolValue) Set(s string) error { *b = boolValue(s); return nil }
func (b *boolValue) IsBoolFlag() bool   { return true }

func readSecret(readFile readFileFunc, path, from string) (string, error) {
	if readFile == nil {
		return "", errorf("%s: secret files are not available", from)
	}
	b, err := readFile(path)
	if err != nil {
		return "", errorf("%s: cannot read secret file: %v", from, err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func checkUnknownEnv(reg []Setting, env map[string]string) error {
	known := map[string]bool{}
	for _, s := range reg {
		known[s.Env()] = true
		if s.Secret {
			known[s.Env()+"_FILE"] = true
		}
	}
	var unknown []string
	for k := range env {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	msgs := make([]string, 0, len(unknown))
	for _, k := range unknown {
		m := "unknown setting " + k
		if s := suggest(k, known); s != "" {
			m += " (did you mean " + s + "?)"
		}
		msgs = append(msgs, m)
	}
	return errorf("%s", strings.Join(msgs, "; "))
}

func suggest(name string, known map[string]bool) string {
	best, bestD := "", 4
	for k := range known {
		if d := distance(name, k); d < bestD || (d == bestD && k < best) {
			best, bestD = k, d
		}
	}
	return best
}

// distance is the Levenshtein edit distance.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
