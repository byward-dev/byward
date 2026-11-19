package logging

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// MarkedURL shows a URL setting as URL does, with a marker for each part left out, so the reader
// knows the value holds more than is shown, and never the part itself (#458).
func TestAMarkedURLShowsWhatItLeavesOut(t *testing.T) {
	for raw, want := range map[string]string{
		"https://up.example/mcp":                          "https://up.example/mcp",
		"https://up.example/mcp?api_key=S3CRET":           "https://up.example/mcp?…",
		"https://up.example/mcp?":                         "https://up.example/mcp?…",
		"https://up.example/mcp#S3CRET":                   "https://up.example/mcp#…",
		"https://up.example/mcp;jsessionid=S3CRET":        "https://up.example/mcp;…",
		"https://up.example/mcp;s=S3CRET?k=S3CRET#S3CRET": "https://up.example/mcp;…?…#…",
		"https://up.example/a%3Bb":                        "https://up.example/a%3Bb",
		"https://up.example/mcp?q=a#b?c":                  "https://up.example/mcp?…#…",
		"not a url?S3CRET":                                Hidden,
		"https://idp.example/@tenant?k=S3CRET":            Hidden, // an @ past the host: URL shows nothing
		"https://up.example/mcp#":                         "https://up.example/mcp#…",
		"https://up.example/mcp?k=a;S3CRET":               "https://up.example/mcp?…",
		"https://up.example/a\u2028b":                     "https://up.example/a%E2%80%A8b", // #505: never a character that is not printable
		"https://a\u0085b.example/":                       "https://a%C2%85b.example/",
		"https://up.example/a\xffb":                       "https://up.example/a%FFb",
		"https://up.example/\nx":                          Hidden,
	} {
		if got := MarkedURL(raw); got != want {
			t.Errorf("MarkedURL(%q) = %q, want %q", raw, got, want)
		}
		if strings.Contains(MarkedURL(raw), "S3CRET") {
			t.Errorf("MarkedURL(%q) shows the secret", raw)
		}
	}
}

// FileError names a file's error by its cause alone, never its path, which may be a secret pasted
// where the path belongs; errors.Is still finds the cause (#461).
func TestAFileErrorLeavesOutThePath(t *testing.T) {
	const pasted = "Xq9-S3CRETPW~value"
	_, err := os.ReadFile(filepath.Join(t.TempDir(), pasted))
	got := FileError(err)
	if got.Error() != "no such file or directory" || !errors.Is(got, fs.ErrNotExist) {
		t.Errorf("FileError = %v, want the cause alone, still fs.ErrNotExist", got)
	}
	if wrapped := FileError(fmt.Errorf("reading: %w", err)); wrapped.Error() != "no such file or directory" {
		t.Errorf("FileError of a wrapped path error = %v, want the cause alone", wrapped)
	}
	if other := errors.New("not a path error"); FileError(other) != other {
		t.Errorf("FileError changed an error that is not a *fs.PathError")
	}
	if FileError(nil) != nil {
		t.Errorf("FileError(nil) is not nil")
	}
}
