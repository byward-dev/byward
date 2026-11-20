package config

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// canaryText stands for a secret given as a setting's value; no other text in these tests holds it.
const canaryText = "OPQ7CANARY"

// holdsCanary reports whether text holds canaryText in any case: a refusal could lower-case it.
func holdsCanary(text string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(canaryText))
}

// Every way Go formats or encodes a value shows an Opaque only by its length (ADR-0031 §1): each fmt
// verb, slog's text and JSON handlers, encoding/json and encoding.TextMarshaler. The value alone is
// shown as exactly its length, so no encoding of the text (hex, base64) passes; inside a struct,
// exported or not, a slice or a map, each holds the length and never the text. Only raw returns it.
func TestAnOpaqueValueIsShownOnlyByItsLength(t *testing.T) {
	o := NewOpaque("https://u:" + canaryText + "@h.example/x")
	const shown = "(32 characters, not shown)"
	j, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var tm encoding.TextMarshaler = o
	b, err := tm.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	exact := map[string]struct{ got, want string }{
		"String":      {o.String(), shown},
		"GoString":    {o.GoString(), "config.Opaque" + shown},
		"Sprint":      {fmt.Sprint(o), shown},
		"Sprintln":    {fmt.Sprintln(o), shown + "\n"},
		"json":        {string(j), `"` + shown + `"`},
		"MarshalText": {string(b), shown},
	}
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X", "%d", "%10.3s"} {
		exact[verb] = struct{ got, want string }{fmt.Sprintf(verb, o), shown}
	}
	for how, e := range exact {
		if e.got != e.want {
			t.Errorf("%s shows %q, want %q", how, e.got, e.want)
		}
	}
	type holder struct {
		Exported   Opaque
		unexported Opaque
	}
	h := holder{o, o}
	held := map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
		held[verb+" of a struct"], held[verb+" of a pointer to it"] = fmt.Sprintf(verb, h), fmt.Sprintf(verb, &h)
	}
	for name, handler := range map[string]func(*bytes.Buffer) slog.Handler{
		"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"slog JSON": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var b bytes.Buffer
		slog.New(handler(&b)).Info("m", "value", o, "holder", h, slog.Any("any", o))
		held[name] = b.String()
	}
	for name, v := range map[string]any{"json of a struct": h, "json of a slice": []Opaque{o}, "json of a map": map[string]Opaque{"k": o}} {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		held[name] = string(j)
	}
	for how, text := range held {
		if !strings.Contains(text, shown) || holdsCanary(text) {
			t.Errorf("%s shows %q, want the length %s and never the text", how, text, shown)
		}
	}
	if o.raw() != "https://u:"+canaryText+"@h.example/x" {
		t.Errorf("raw = %q, want the text as given", o.raw())
	}
}

// An Opaque tells empty, blank and other text apart; the zero Opaque and one set to nothing are both
// empty.
func TestAnOpaqueValueTellsEmptyAndBlankApartAndCountsCharacters(t *testing.T) {
	for _, tc := range []struct {
		name         string
		o            Opaque
		empty, blank bool
		shown        string
	}{
		{"the zero value", Opaque{}, true, true, "(empty)"},
		{"set to nothing", NewOpaque(""), true, true, "(empty)"},
		{"white space", NewOpaque(" \t"), false, true, "(2 characters, not shown)"},
		{"one character", NewOpaque("x"), false, false, "(1 character, not shown)"},
		{"a character that is not ASCII, counted once", NewOpaque("ü"), false, false, "(1 character, not shown)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.empty && tc.o.raw() != "" {
				t.Errorf("raw = %q, want nothing", tc.o.raw())
			}
			if tc.o.empty() != tc.empty || tc.o.blank() != tc.blank || tc.o.String() != tc.shown {
				t.Errorf("Empty %v, Blank %v, shown %q; want %v, %v, %q", tc.o.empty(), tc.o.blank(), tc.o.String(), tc.empty, tc.blank, tc.shown)
			}
		})
	}
}
