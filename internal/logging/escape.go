package logging

import (
	"io"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// jsonEscaper writes each JSON log line with every rune strconv.IsPrint rejects, such as a Unicode
// format character (U+202E, U+200B, U+FEFF), as a JSON \uXXXX escape (#690). slog's JSON handler
// writes those raw, so a terminal would show the line reordered or with hidden characters; the text
// handler already quotes them. The escape is JSON's own, so the line still decodes to the same
// value, and the same value always logs the same way.
//
// It rewrites encoded bytes, which is safe because every JSON structural byte is ASCII: a rune at or
// above U+0080 can only be inside a string. It relies on slog writing each record in one Write, as
// JSONHandler.Handle documents (Go 1.27.4, log/slog/handler.go:321), and as valid UTF-8 (slog writes
// an invalid byte as U+FFFD). A byte that does not decode, as half of a rune split across two
// Writes would be, is written through unchanged.
type jsonEscaper struct{ w io.Writer }

func (e jsonEscaper) Write(p []byte) (int, error) {
	var out []byte // nil until a rune needs escaping
	start := 0
	for i := 0; i < len(p); {
		if p[i] < utf8.RuneSelf && p[i] != 0x7f { // ASCII below DEL: slog has escaped what needs it
			i++
			continue
		}
		r, size := utf8.DecodeRune(p[i:])
		if r == utf8.RuneError && size == 1 || strconv.IsPrint(r) {
			i += size
			continue
		}
		out = append(out, p[start:i]...)
		out = appendJSONEscape(out, r)
		i += size
		start = i
	}
	if out == nil {
		return e.w.Write(p)
	}
	if _, err := e.w.Write(append(out, p[start:]...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// appendJSONEscape appends r as JSON writes it escaped: \u and four lowercase hex digits, as slog
// writes U+2028, or a UTF-16 surrogate pair above U+FFFF.
func appendJSONEscape(b []byte, r rune) []byte {
	const hex = "0123456789abcdef"
	if r1, r2 := utf16.EncodeRune(r); r1 != utf8.RuneError {
		b = appendJSONEscape(b, r1)
		r = r2
	}
	return append(b, '\\', 'u', hex[r>>12&0xf], hex[r>>8&0xf], hex[r>>4&0xf], hex[r&0xf])
}
