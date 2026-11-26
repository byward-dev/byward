// Package config loads the proxy's settings from flags, `BYWARD_*` environment variables
// and defaults, from one registry that also drives validation and redaction (ADR-0020).
package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/byward-dev/byward/internal/logging"
)

// EnvPrefix starts every environment variable the proxy reads.
const envPrefix = "BYWARD_"

// Setting is one registry entry. Every setting has a flag and an env name.
type Setting struct {
	Name    string // flag name, kebab-case; the env name is derived from it
	Group   Group  // the section of the settings reference it is listed in; the two upstream groups also mean "for that mode only", as does httpOnly (offModeSettings)
	Default string
	Help    string
	Bool    bool
	// Auth marks settings that configure authentication (IdP, broker); --insecure-no-auth refuses
	// to start when any of them is set, so a half-configured production setup never runs open.
	Auth bool
	// EmptyIsGiven keeps the setting's variable set to nothing as given, for the rare setting whose
	// Help gives empty a meaning of its own. Otherwise (the rule) set to nothing is as if unset, since
	// env templates list every variable (#428).
	EmptyIsGiven bool
	// StdioHint is the refusal of the setting beside a stdio upstream, which it has no effect on, for a
	// setting outside the upstream groups whose refusal says what to use instead (offModeSettings). It
	// is fixed text, with %[1]s for the setting as the operator gave it and no other verb
	// (checkStdioHints, at init), so it never shows a value.
	StdioHint string
	// shape decides how the value is shown (ADR-0031 §3); secretShape also means the value is read
	// only from a file. Every registry entry has one (checkShapes, at init).
	shape *shape
}

// Secret reports whether the setting is a secret: read only from a file, `<ENV>_FILE` or
// `--<name>-file`, and never shown. Its shape decides it.
func (s Setting) Secret() bool { return s.shape == secretShape }

// HoldsPath reports whether the setting's value is a path the proxy reads or writes: a file that
// cannot be used is named by the setting and the cause, never the path (security invariant 2, #587).
// Its shape decides it. A secret's file is a path too, given as `<ENV>_FILE` or `--<name>-file`,
// but the secret has the secret shape, so HoldsPath is false for it; PathVariables lists its file.
func (s Setting) HoldsPath() bool { return s.shape == pathShape }

// PathVariables are the environment variables whose values are paths: each path setting's, and each
// secret's `<ENV>_FILE` (security invariant 2, #587). A test requires a leak-test scenario for each.
func PathVariables() []string {
	var out []string
	for _, s := range registry {
		switch {
		case s.HoldsPath():
			out = append(out, s.Env())
		case s.Secret():
			out = append(out, s.FileEnv())
		}
	}
	return out
}

// Env is the setting's environment variable name.
func (s Setting) Env() string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(s.Name, "-", "_"))
}

// FileEnv is a secret's file variable, `<ENV>_FILE`: the environment variable that names the file its
// secret is read from, as the flag `--<name>-file` does (#506). It panics for a setting that is not a
// secret, which has none, so a name built for the wrong setting fails the first test that reaches it.
func (s Setting) FileEnv() string {
	if !s.Secret() {
		panic("config: " + s.Name + " is not a secret, so it has no _FILE variable")
	}
	return s.Env() + "_FILE"
}

// FileFlag is a secret's file flag, `<name>-file` (given as `--<name>-file`): the flag that names the
// file its secret is read from, as FileEnv's variable does (#506). It panics for a setting that is not a
// secret, which has none.
func (s Setting) FileFlag() string {
	if !s.Secret() {
		panic("config: " + s.Name + " is not a secret, so it has no -file flag")
	}
	return s.Name + "-file"
}

// EnvToSet is the environment variable an operator is told to set for the setting: its file variable for
// a secret, its own for any other. Value.From, by contrast, names the flag or variable a secret's file
// actually came by.
func (s Setting) EnvToSet() string {
	if s.Secret() {
		return s.FileEnv()
	}
	return s.Env()
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
	Given   Opaque // the value as given; only its parser and its shape read the text (Opaque.raw)
	Source  Source
	Path    string // the file a SourceFile secret was read from
	From    string // how that file was named: the flag or the env variable, for error messages
}

// SecretFile is a file a secret was read from, and the flag or env variable that named it.
type SecretFile struct{ From, Path string }

// SecretFiles lists the files secrets were read from, in registry order; the server checks their
// permissions (ADR-0018 §11). It also lists the file of a secret refused for the upstream mode that
// is off, which resolve never opens; harmless, as Load fails on that refusal.
func (v *Values) SecretFiles() []SecretFile {
	var out []SecretFile
	for _, n := range v.order {
		if val := v.byKey[n]; val.Source == SourceFile {
			out = append(out, SecretFile{From: val.From, Path: val.Path})
		}
	}
	return out
}

// Display is the value as the startup log and --print-config show it: only through its setting's
// shape (ADR-0031 §3), on one line of printable characters, which --print-config relies on (#505).
// An unset value shows as nothing, and the value of a Setting built without a shape (outside the
// registry, which gives every entry one) as Hidden.
func (v Value) Display() string {
	switch {
	case v.Given.empty():
		return ""
	case v.Setting.shape == nil:
		return logging.Hidden
	}
	return v.Setting.shape.display(v.Given.raw())
}

// display is the named setting's value as its shape shows it (Value.Display), for a log line that
// names a setting's value. Like value, it panics on a name these Values do not hold: a caller outside
// load checks holds first (Config.ShownIssuer), so a Config built by hand shows as Hidden.
func (v *Values) display(name string) string { return v.value(name).Display() }

// lookup is the registry entry of name; it panics on a name the registry lacks, which tests catch.
func lookup(name string) Setting {
	for _, s := range registry {
		if s.Name == name {
			return s
		}
	}
	panic("config: no setting " + name)
}

// configError is a configuration error; the process exits with its own code for these.
type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

func errorf(format string, a ...any) error { return &configError{msg: fmt.Sprintf(format, a...)} }

// bothSet is the refusal of two settings, or two forms of one, given where one is wanted.
func bothSet(a, b string) error { return errorf("%s and %s are both set; give one of them", a, b) }

// Values holds the resolved registry.
type Values struct {
	order []string
	byKey map[string]Value
	// command is the stdio upstream's argv given after --; its Value shows it for display only.
	command []string
}

// value is the named setting's Value, for its parser. It panics on a name these Values do not hold,
// which every test that loads the setting catches, so a parser never gets a Value without a shape. A
// setting refused for the upstream mode that is off is read as its default: refused, it is not
// parsed, so its refusal is its one error (offModeSettings, #631).
func (v *Values) value(name string) Value {
	val, ok := v.byKey[name]
	if !ok {
		panic("config: no setting " + name)
	}
	if v.refusedOffMode(name) {
		return Value{Setting: val.Setting, Given: NewOpaque(val.Setting.Default), Source: SourceDefault}
	}
	return val
}

// holds reports whether these Values hold the named setting: loaded Values hold every one, a Config
// built by hand none.
func (v *Values) holds(name string) bool {
	if v == nil {
		return false
	}
	_, ok := v.byKey[name]
	return ok
}

// empty reports whether the named setting's value is empty: unset, or set to nothing. A setting refused
// for the upstream mode that is off is read as its default, as value reads it (#631).
func (v *Values) empty(name string) bool { return v.value(name).Given.empty() }

// given reports whether the operator gave the named setting a value, or a file for a secret, which is
// given even when it is empty, so it never falls back to another choice. A setting refused for the
// upstream mode that is off is not given here, as value reads it as its default: refused, it is not
// checked further (#631). A variable set to nothing never reaches here (resolve takes it as unset,
// Setting.EmptyIsGiven), nor does a _FILE variable set to nothing, which names no file. A flag set to
// nothing is not given here, though a check that reads its Source counts it: every check that refuses
// a family's settings while the family is off does.
func (v *Values) given(name string) bool {
	if v.refusedOffMode(name) {
		return false
	}
	val := v.byKey[name]
	return !val.Given.empty() || val.Path != ""
}

// spelled names a setting as the operator gave it: the flag, the file setting or the environment
// variable.
func spelled(val Value) string {
	switch {
	case val.From != "":
		return val.From
	case val.Source == SourceFlag:
		return "--" + val.Setting.Name
	}
	return val.Setting.Env()
}

// NameAsGiven names the setting called name as the operator gave it, for any message that names it:
// a refusal, a warning or a doctor fix (#619). That is the flag or variable that gave it (spelled), so
// a bad --oidc-client-key-file is not named BYWARD_OIDC_CLIENT_KEY_FILE. A setting left at its
// default, or nil Values (a Config built by hand), names the variable to set (EnvToSet), from the
// Values' own Setting where they hold it. It panics for a name neither they nor the registry hold.
func (v *Values) NameAsGiven(name string) string {
	if v == nil {
		return lookup(name).EnvToSet()
	}
	val, ok := v.byKey[name]
	switch { // from v's own Setting: Values resolved over another registry hold settings lookup does not
	case !ok:
		return lookup(name).EnvToSet()
	case val.Source == SourceDefault:
		return val.Setting.EnvToSet()
	}
	return spelled(val)
}

// emptySecretFile is the error for a secret setting whose named file holds nothing, or only
// whitespace, naming the setting as the operator gave it; nil otherwise.
func (v *Values) emptySecretFile(name string) error {
	switch val := v.byKey[name]; {
	case val.Path == "" || v.refusedOffMode(name): // refused, its file is never read (readSecretFiles)
		return nil
	case val.Given.empty():
		return errorf("%s: the file is empty", val.From)
	case val.Given.blank():
		return errorf("%s: the file holds only whitespace", val.From)
	}
	return nil
}

// boolean reads a true/false setting. Every setting read this way must be Bool in the registry, so a
// bare --name means true (TestBooleanSettingsAreExactlyTheBoolFlags, TestEveryBooleanReadIsOfABoolFlag).
func (v *Values) boolean(name string) (bool, error) { return parseBool(v.value(name)) }

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

// readFileFunc reads a secret file; main passes os.ReadFile. Its error must be a *fs.PathError or
// name no path: readSecret shows it through logging.FileError, which removes only that path (#461).
type readFileFunc = func(path string) ([]byte, error)

// resolve applies flags > env > defaults over a registry. extraFlags registers command-line-only
// flags (actions such as --version) on the same flag set. A secret given inline, not empty, beside
// its file is refused, in development mode too (#590): the file would win in silence. An inline
// secret alone is checkInlineSecrets' to refuse.
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
		if s.Secret() {
			fileFlagVals[s.Name] = fs.String(s.FileFlag(), "", "file holding "+s.Help)
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
		secrets := map[string]Setting{}
		for _, s := range reg {
			if s.Secret() {
				secrets[s.Name] = s
			}
		}
		return nil, flagError(fs, err, secrets)
	}
	if fs.NArg() > 0 {
		return nil, errorf("want settings as --name=value flags, and the stdio upstream command after --; got an unexpected argument %s", notShown(fs.Arg(0)))
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
		v := Value{Setting: s, Given: NewOpaque(s.Default), Source: SourceDefault}
		switch {
		case s.Secret() && set[s.FileFlag()]:
			from := "--" + s.FileFlag()
			if env[s.Env()] != "" { // set to nothing is as if unset (#428)
				return nil, bothSet(s.Env(), from)
			}
			v.Given, v.Source, v.Path, v.From = NewOpaque(""), SourceFile, *fileFlagVals[s.Name], from // read by readSecretFiles
		case !s.Secret() && set[s.Name]:
			v.Given, v.Source = NewOpaque(*flagVals[s.Name]), SourceFlag
		case s.Secret() && env[s.FileEnv()] != "":
			if env[s.Env()] != "" { // set to nothing is as if unset (#428)
				return nil, bothSet(s.Env(), s.FileEnv())
			}
			v.Given, v.Source, v.Path, v.From = NewOpaque(""), SourceFile, env[s.FileEnv()], s.FileEnv() // read by readSecretFiles
		default:
			if e, ok := env[s.Env()]; ok && (e != "" || s.EmptyIsGiven) { // set to nothing is as if unset (Setting.EmptyIsGiven)
				v.Given, v.Source = NewOpaque(e), SourceEnv
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
		// Kept as argv for the upstream; Given holds it as the env form's JSON array, which Display reads
		// (a []string always marshals).
		encoded, _ := json.Marshal(command)
		v.Given, v.Source = NewOpaque(string(encoded)), SourceFlag
		vals.byKey[commandSetting] = v
		vals.command = command
	}
	if err := vals.readSecretFiles(readFile); err != nil {
		return nil, err
	}
	return vals, nil
}

// readSecretFiles reads each secret given by its file, in registry order, once every setting and a
// command after -- are resolved, so the upstream mode is known: the file of a secret refused for the
// mode that is off is never opened (#631), so its refusal is its one error. Such a secret keeps its
// Path, and so is listed by SecretFiles; that is harmless, as Load then fails on the refusal.
func (v *Values) readSecretFiles(readFile readFileFunc) error {
	for _, name := range v.order {
		val := v.byKey[name]
		if val.Source != SourceFile || v.refusedOffMode(name) {
			continue
		}
		raw, err := readSecret(readFile, val.Setting, val.Path, val.From)
		if err != nil {
			return err
		}
		val.Given = NewOpaque(raw)
		v.byKey[name] = val
	}
	return nil
}

// flagError is err, the flag package's refusal of args, without any text of the operator's
// (ADR-0031 §1): "bad flag syntax" quotes the whole argument, an invalid value the value given to a
// flag, and an undefined flag all its text before =, which can be a value pasted as an argument. A
// flag that needs an argument is named, as it is one of the command's own. Any other message the flag
// package may write is refused without its text, so a new one cannot show a value.
func flagError(fs *flag.FlagSet, err error, secrets map[string]Setting) error {
	msg := err.Error()
	if rest, ok := strings.CutPrefix(msg, "bad flag syntax: "); ok {
		return errorf("want flags as --name=value; got an argument with a bad flag syntax %s", notShown(rest))
	}
	if f := refusedFlag(fs, msg); f != nil {
		want := "a value it takes"
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			want = "true, false or no value"
		}
		return errorf("--%s: want %s; got a value it does not take (not shown)", f.Name, want)
	}
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		return errorf("want flags this command takes; got an undefined flag %s%s", notShown(name), flagHint(fs, name, secrets))
	}
	if strings.HasPrefix(msg, "flag needs an argument: -") {
		return errorf("%v", err)
	}
	return errorf("the command line is refused (the flag package's message is not shown)")
}

// flagHint suggests the command's own flag an undefined one most likely meant, never the text given:
// a secret's file flag, with the reason, when the name is the secret's own (secrets, by name); the flag
// the name is only missing -file from (a path setting such as --tls-cert-file); else the nearest name,
// only when it is near enough that the operator, who is not shown the name, can trust it.
func flagHint(fs *flag.FlagSet, name string, secrets map[string]Setting) string {
	if s, ok := secrets[name]; ok {
		return " (secrets come from a file: did you mean --" + s.FileFlag() + "?)"
	}
	if fs.Lookup(name+"-file") != nil { // a path setting's own name ends in -file, such as tls-cert-file
		return " (did you mean --" + name + "-file?)"
	}
	known := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { known[f.Name] = true })
	if s := suggest(name, known); s != "" && distance(name, s) <= len(name)/3 {
		return " (did you mean --" + s + "?)"
	}
	return ""
}

// refusedFlag is the flag msg, the flag package's "invalid boolean value" or "invalid value" error,
// names, or nil. The value comes first, quoted, so the name is read after it: a value holding
// " for -name" cannot name another flag.
func refusedFlag(fs *flag.FlagSet, msg string) *flag.Flag {
	for _, prefix := range []string{"invalid boolean value ", "invalid value "} {
		rest, ok := strings.CutPrefix(msg, prefix)
		if !ok {
			continue
		}
		quoted, err := strconv.QuotedPrefix(rest)
		if err != nil {
			return nil
		}
		rest = strings.TrimPrefix(strings.TrimPrefix(rest[len(quoted):], " for flag -"), " for -")
		if name, _, ok := strings.Cut(rest, ": "); ok {
			return fs.Lookup(name)
		}
	}
	return nil
}

// inlineSecrets lists secret settings given directly in env instead of through a file.
func (v *Values) inlineSecrets() []Setting {
	var out []Setting
	for _, val := range v.Effective() {
		if val.Setting.Secret() && val.Source == SourceEnv && !v.refusedOffMode(val.Setting.Name) { // refused, its refusal (its hint or "remove it") is its one error (#631)
			out = append(out, val.Setting)
		}
	}
	return out
}

// boolValue is a boolean flag (`--dev`, `--dev=false`) kept as a string for validation.
type boolValue string

func (b *boolValue) String() string     { return string(*b) }
func (b *boolValue) Set(s string) error { *b = boolValue(s); return nil }
func (b *boolValue) IsBoolFlag() bool   { return true }

// readSecret reads the secret setting s from the file at path, given as from: its _FILE
// variable or its -file flag.
func readSecret(readFile readFileFunc, s Setting, path, from string) (string, error) {
	if readFile == nil {
		return "", errorf("%s: secret files are not available", from)
	}
	b, err := readFile(path)
	if err != nil {
		// The path is not shown: a secret pasted where its file's path belongs would be (#461). A
		// relative one is read from the working directory, which a secret pasted there always is.
		reason := fmt.Sprintf("it cannot be read: %v", logging.FileError(err))
		if !filepath.IsAbs(path) {
			reason += "; it is a relative path, read from the working directory"
		}
		return "", refusedFormAs(from, s, whole, path, "the path of a file holding the secret, such as /run/secrets/"+s.Name, reason)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func checkUnknownEnv(reg []Setting, env map[string]string) error {
	known := map[string]bool{}
	for _, s := range reg {
		known[s.Env()] = true
		if s.Secret() {
			known[s.FileEnv()] = true
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
