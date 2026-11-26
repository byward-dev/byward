package config

import "fmt"

// entry places a refused value in its setting: the value itself (of is 0), or entry i+1 of a list of
// of entries.
type entry struct{ i, of int }

// whole is a setting's value as one, not an entry of a list.
var whole = entry{}

// refusedForm is the refusal of raw, val's text or one of its entries, for its form (ADR-0031 §1), in
// the one format "<setting>: want …; got …": what val's setting wants, where the value is, what its shape shows of
// a refused value (its length) and the parser's reason, a clause such as "it has no host". want and
// reason are the parser's fixed text: nothing from the value may reach them, but for an IP address as
// a browser reads or writes it ("browsers read it as 127.0.0.1", "write it as [::1]"), which carries
// nothing but the address. An empty value is refused as nothing given. The setting is named as
// the operator gave it (Value.nameAsGiven, #623).
func refusedForm(val Value, at entry, raw, want, reason string) error {
	return refusedFormAs(val.nameAsGiven(), val.Setting, at, raw, want, reason)
}

// refusedFormAs is refusedForm naming the setting as name, for a refusal made before the setting has a
// Value: a secret's file, named by the file setting it was read through.
func refusedFormAs(name string, s Setting, at entry, raw, want, reason string) error {
	if raw == "" {
		return errorf("%s: want %s; got nothing", name, want)
	}
	return errorf("%s: want %s; got %s %s: %s", name, want, at, s.shape.refused(raw), reason)
}

// listsNothing refuses a list setting that is set but names no entry, such as ",": it would read as
// unset, and a gate list would silently open the gate.
func listsNothing(val Value) error {
	return errorf("%s: want at least one entry; got a list of none", val.nameAsGiven())
}

// refusedMeaning is the refusal of a value that parsed, for its meaning (ADR-0031 §1), in the same
// format: shown is the value as the parser read it, never as the operator wrote it. The setting
// is named as the operator gave it.
func refusedMeaning(val Value, at entry, shown, want, reason string) error {
	if at.of == 0 {
		return errorf("%s: want %s; got %s: %s", val.nameAsGiven(), want, shown, reason)
	}
	return errorf("%s: want %s; got %s, %s: %s", val.nameAsGiven(), want, at, shown, reason)
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
