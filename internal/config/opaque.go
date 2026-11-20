package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Opaque is a setting's value as the operator gave it (ADR-0031 §1). Every way Go formats or encodes
// a value shows only its length: fmt's verbs (Format, which fmt prefers to String and GoString), slog
// (LogValue, which both handlers prefer; the JSON handler never calls String), encoding/json
// (MarshalJSON) and encoding.TextMarshaler. The text sits behind a pointer, so fmt or json walking a
// struct that holds an Opaque finds an address, never the text. Only raw returns it, and only a
// setting's parser, or its shape's display, calls raw (TestOnlyParsersReadARawValue); raw is
// unexported, so no other package can read the text at all. Hold it by value: through a nil *Opaque,
// slog's call of LogValue panics.
type Opaque struct{ p *string }

// NewOpaque holds text as a setting's given value.
func NewOpaque(text string) Opaque { return Opaque{p: &text} }

// raw is the text as given. Call it only from the setting's parser, which turns it into the accepted
// value or into a refusal that never repeats it, or from its shape's display.
func (o Opaque) raw() string {
	if o.p == nil {
		return ""
	}
	return *o.p
}

// empty reports whether nothing was given.
func (o Opaque) empty() bool { return o.p == nil || *o.p == "" }

// blank reports whether the text is empty or only white space.
func (o Opaque) blank() bool { return o.p == nil || strings.TrimSpace(*o.p) == "" }

func (o Opaque) shown() string {
	if o.empty() {
		return "(empty)"
	}
	return notShown(*o.p)
}

func (o Opaque) String() string               { return o.shown() }
func (o Opaque) GoString() string             { return "config.Opaque" + o.shown() }
func (o Opaque) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, o.shown()) }
func (o Opaque) LogValue() slog.Value         { return slog.StringValue(o.shown()) }
func (o Opaque) MarshalJSON() ([]byte, error) { return json.Marshal(o.shown()) }
func (o Opaque) MarshalText() ([]byte, error) { return []byte(o.shown()), nil }
