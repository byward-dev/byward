package config

import "fmt"

// entry places a refused value in its setting: the value itself (of is 0), or entry i+1 of a list of
// of entries.
type entry struct{ i, of int }

// whole is a setting's value as one, not an entry of a list.
var whole = entry{}

// refusedForm is the refusal of raw, s's value or one of its entries, for its form (ADR-0031 §1), in
// the one format "<setting>: want …; got …": what s wants, where the value is, what s's shape shows of
// a refused value (its length) and the parser's reason, a clause such as "it has no host". want and
// reason are the parser's fixed text: nothing from the value may reach them, but for an IP address the
// parser rewrote, as browsers write it ("write it as 127.0.0.1"), which carries nothing but the
// address. An empty value is refused as nothing given.
func refusedForm(s Setting, at entry, raw, want, reason string) error {
	if raw == "" {
		return errorf("%s: want %s; got nothing", s.Env(), want)
	}
	return errorf("%s: want %s; got %s %s: %s", s.Env(), want, at, s.shape.refused(raw), reason)
}

// refusedMeaning is the refusal of a value that parsed, for its meaning (ADR-0031 §1), in the same
// format: shown is the value as the parser read it, never as given.
func refusedMeaning(s Setting, at entry, shown, want, reason string) error {
	if at.of == 0 {
		return errorf("%s: want %s; got %s: %s", s.Env(), want, shown, reason)
	}
	return errorf("%s: want %s; got %s, %s: %s", s.Env(), want, at, shown, reason)
}

// and names two places in the same list: "entries 1 and 3 of 3".
func (at entry) and(other entry) string {
	return fmt.Sprintf("entries %d and %d of %d", at.i+1, other.i+1, at.of)
}

// String names the place: "a value", or "entry 2 of 3".
func (at entry) String() string {
	if at.of == 0 {
		return "a value"
	}
	return fmt.Sprintf("entry %d of %d", at.i+1, at.of)
}

// parseEntries splits val, a comma-separated list setting, into its entries, each with its place in
// the list. A value set but naming no entry, such as ",", is refused (listsNothing).
func parseEntries(val Value) ([]string, func(i int) entry, error) {
	raw := val.Given.raw()
	list := splitList(raw)
	if raw != "" && len(list) == 0 {
		return nil, nil, listsNothing(val.Setting)
	}
	return list, func(i int) entry { return entry{i, len(list)} }, nil
}

// listsNothing refuses a list setting that is set but names no entry, such as ",": it would read as
// unset, and a gate list would silently open the gate.
func listsNothing(s Setting) error {
	return errorf("%s: want at least one entry; got a list of none", s.Env())
}
