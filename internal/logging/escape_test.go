package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A format or other non-printable character a user or client puts in a logged string never reaches
// the terminal raw, in either format, wherever the string is logged (#690). It is shown as a visible
// \u escape, which in JSON is JSON's own, so the line still decodes to the value logged. A string
// with no such character logs unchanged.
func TestAFormatCharacterIsLoggedEscapedAndTheValueIsKept(t *testing.T) {
	for _, row := range []struct {
		value  string
		escape string // how each format shows the character; "" if the value logs unchanged
	}{
		{"al\u202eice@example.com", `\u202e`}, // RIGHT-TO-LEFT OVERRIDE
		{"a\u200bb", `\u200b`},                // ZERO WIDTH SPACE
		{"\ufeffbob", `\ufeff`},               // BYTE ORDER MARK
		{"jo\u00adhn", `\u00ad`},              // SOFT HYPHEN
		{"a\u009bb", `\u009b`},                // CONTROL SEQUENCE INTRODUCER: a C1 control, not Cf
		{"j\u00f6hn@ex\u00e4mple.com", ""},
		{"Jos\u00e9", ""},
	} {
		for _, at := range []struct {
			name string
			log  func(*slog.Logger, string)
			key  string // the key the value is under in the JSON line; "" if the allowlist drops it
		}{
			{"message", func(l *slog.Logger, v string) { l.Info(v) }, slog.MessageKey},
			{"attribute", func(l *slog.Logger, v string) { l.Info("x", "user_key", v) }, "user_key"},
			{"grouped attribute", func(l *slog.Logger, v string) { l.Info("x", slog.Group("g", "user_key", v)) }, ""},
		} {
			for _, format := range []string{"json", "text"} {
				t.Run(strconv.Quote(row.value)+"/"+at.name+"/"+format, func(t *testing.T) {
					var buf bytes.Buffer
					at.log(New(&buf, format), row.value)
					line := buf.String()
					if i := strings.IndexFunc(line, func(r rune) bool { return r != '\n' && !strconv.IsPrint(r) }); i >= 0 {
						t.Fatalf("raw %q in %q", []rune(line[i:])[0], line)
					}
					shown := at.key != ""
					if !shown && strings.Contains(line, "user_key") {
						t.Fatalf("a grouped attribute is logged: %q", line)
					}
					if row.escape == "" && shown && !strings.Contains(line, row.value) {
						t.Errorf("%q is not logged unchanged: %q", row.value, line)
					}
					if row.escape != "" && shown && !strings.Contains(line, row.escape) {
						t.Errorf("no visible %s in %q", row.escape, line)
					}
					if row.escape != "" && shown && format == "text" && !strings.Contains(line, strconv.Quote(row.value)) {
						t.Errorf("text line %q does not hold %s quoted", line, strconv.Quote(row.value))
					}
					if format != "json" || !shown {
						return
					}
					var decoded map[string]any
					if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
						t.Fatalf("not JSON: %v: %q", err, line)
					}
					if decoded[at.key] != row.value {
						t.Errorf("%s decodes to %q, want %q", at.key, decoded[at.key], row.value)
					}
				})
			}
		}
	}
}

// Above U+FFFF, the JSON escape is a UTF-16 surrogate pair, as JSON requires.
func TestAFormatCharacterAboveTheBMPIsASurrogatePair(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "json").Info("x", "user_key", "a\U000e0001b") // LANGUAGE TAG, a format character
	if !strings.Contains(buf.String(), `"user_key":"a\udb40\udc01b"`) {
		t.Fatalf("not a surrogate pair: %q", buf.String())
	}
}

// Write rewrites only the runes it escapes, DEL included, which slog writes raw; a byte that does
// not decode as UTF-8, such as half of a rune split across two writes, is written through as it is.
// Either way it reports the whole line written, as io.Writer requires.
func TestWriteRewritesOnlyWhatItEscapesAndReportsTheWholeLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain", "plain"},
		{"a\u202eb", `a\u202eb`},
		{"a\u202eb\u200bc", `a\u202eb\u200bc`},
		{"a\x7fb", `a\u007fb`},
		{"\xe2\x80", "\xe2\x80"},
		{"a\xffb", "a\xffb"},
		{"\u00e9\xe2", "\u00e9\xe2"},
	} {
		var buf bytes.Buffer
		if n, err := (jsonEscaper{&buf}).Write([]byte(tc.in)); n != len(tc.in) || err != nil || buf.String() != tc.want {
			t.Errorf("Write(%q) = %d, %v, wrote %q; want %d, nil, %q", tc.in, n, err, buf.String(), len(tc.in), tc.want)
		}
	}
}

// failingWriter is the shape of cmd/byward's failingWriter (downstream_test.go), with the error
// given; extract it into internal/testutil at the third caller.
type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// A line the writer fails to take reports the writer's error, and Write reports that none of it
// was written, whether or not the line needed escaping.
func TestAFailedWriteReportsItsError(t *testing.T) {
	broken := errors.New("disk full")
	for _, v := range []string{"plain", "al\u202eice"} {
		r := slog.NewRecord(time.Now(), slog.LevelInfo, "x", 0)
		r.AddAttrs(slog.String("user_key", v))
		if err := New(failingWriter{broken}, "json").Handler().Handle(context.Background(), r); !errors.Is(err, broken) {
			t.Errorf("%q: Handle = %v, want %v", v, err, broken)
		}
		if n, err := (jsonEscaper{failingWriter{broken}}).Write([]byte(v)); n != 0 || !errors.Is(err, broken) {
			t.Errorf("%q: Write = %d, %v; want 0, %v", v, n, err, broken)
		}
	}
}
