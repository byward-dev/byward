//go:build linux || darwin

package stdio

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

var rewritePaths = []jsonPath{{"id"}, {"params", "_meta", "progressToken"}, {"params", "requestId"}}

func TestLocateFindsTargetedValuesAndKeepsEveryOtherByte(t *testing.T) {
	msg := []byte(`{ "z":1, "params" : {"x":[{"id":9}], "_meta":{"progressToken" :"pA", "k":true}}, "id": 7 }`)
	at, err := locate(msg, rewritePaths...)
	if err != nil {
		t.Fatal(err)
	}
	if string(at[0].value(msg)) != "7" || string(at[1].value(msg)) != `"pA"` || at[2] != nil {
		t.Fatalf("located %q, %q, %v", at[0].value(msg), at[1].value(msg), at[2])
	}
	got := replace(msg, edit{at[0], []byte(`"byw-1"`)}, edit{at[1], []byte(`"byw-t1"`)})
	want := `{ "z":1, "params" : {"x":[{"id":9}], "_meta":{"progressToken" :"byw-t1", "k":true}}, "id": "byw-1" }`
	if string(got) != want {
		t.Fatalf("rewritten\n%s\nwant\n%s", got, want)
	}
}

func TestLocateRefusesWhatItCannotPlaceWithCertainty(t *testing.T) {
	for name, msg := range map[string]string{
		"duplicate id":                  `{"id":1,"method":"x","id":2}`,
		"duplicate untargeted root key": `{"jsonrpc":"2.0","jsonrpc":"2.0","id":1}`,
		"duplicate params":              `{"id":1,"params":{},"params":{"_meta":{"progressToken":1}}}`,
		"duplicate progressToken":       `{"id":1,"params":{"_meta":{"progressToken":1,"progressToken":2}}}`,
		"object id":                     `{"id":{"a":1}}`,
		"object progressToken":          `{"id":1,"params":{"_meta":{"progressToken":{}}}}`,
		"array progressToken":           `{"id":1,"params":{"_meta":{"progressToken":[1]}}}`,
		"duplicate _meta":               `{"id":1,"params":{"_meta":{},"_meta":{"progressToken":1}}}`,
		"id in another case":            `{"ID":1}`,
		"params in another case":        `{"id":1,"Params":{"_meta":{"progressToken":1}}}`,
		"token in another case":         `{"id":1,"params":{"_meta":{"progresstoken":1}}}`,
		"not an object":                 `[{"id":1}]`,
		"malformed":                     `{"id":1,`,
		"trailing data":                 `{"id":1} {"id":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := locate([]byte(msg), rewritePaths...); !errors.Is(err, errAmbiguous) {
				t.Fatalf("locate = %v, want errAmbiguous", err)
			}
		})
	}
}

func TestDuplicateKeysOffTheTargetedPathsAreLeftToTheUpstream(t *testing.T) {
	msg := []byte(`{"id":1,"params":{"arguments":{"a":1,"a":2}}}`)
	if _, err := locate(msg, rewritePaths...); err != nil {
		t.Fatalf("locate = %v; a duplicate inside tool arguments is not ours to judge", err)
	}
}

// idKey gives one key per JSON value (L156): equal values however written share it, and different
// values, or a string and an integer, never do, even where encoding/json would decode both to U+FFFD.
func TestIDKeyIsOneKeyPerValue(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{`-0`, `0`, true},
		{` 1 `, `1`, true},
		{`"\u00e9"`, `"é"`, true},
		{`"\/x"`, `"/x"`, true},
		{`"a\u003cb"`, `"a<b"`, true},
		{`-1`, `1`, false},
		{`10`, `1`, false},
		{`"0"`, `0`, false},
		{`"-0"`, `-0`, false},
		{`"-0"`, `"0"`, false},
		{`9007199254740993`, `9007199254740992`, false},
		// What names no character keeps a key of its own instead of U+FFFD (L173).
		{`"\ud800"`, `"\udc00"`, false},
		{`"\ud800"`, `"\ufffd"`, false},
		{`"\ud800"`, `"\uD800"`, true},
		{`"\ud800A"`, `"\ud800\u0041"`, true},
		{`"\udc00\ud800"`, `"\ud800\udc00"`, false},
		{"\"\xff\"", "\"\xfe\"", false},
		{"\"\xff\"", `"\ufffd"`, false},
		{"\"\xff\"", `"\\xff"`, false},
		{`"\ud800"`, `"\\ud800"`, false},
		{`"\udc00\udc00"`, `"\ufffd"`, false},
		{`"\ud800\ue000"`, `"\ufffd"`, false},
		{"\"\xef\"", "\"\xef\xbf\xbd\"", false},
		{"\"\xed\xa0\x80\"", `"\ud800"`, false},
		// A surrogate pair is the character it encodes, in either case.
		{`"\ud83d\ude00"`, `"😀"`, true},
		{`"\uD83D\uDE00"`, `"😀"`, true},
		// An escaped quote, backslash or control character is the key of its short escape.
		{`"\u0022\n"`, `"\"\u000a"`, true},
		{`"\u005c"`, `"\\"`, true},
	} {
		ka, kb := idKey(json.RawMessage(tc.a)), idKey(json.RawMessage(tc.b))
		if got := ka == kb; got != tc.same {
			t.Errorf("idKey(%s) = %s, idKey(%s) = %s: equal %v, want %v", tc.a, ka, tc.b, kb, got, tc.same)
		}
	}
}

// FuzzIDKeyIsOneKeyPerValue: two string ids share a key exactly when they are one JSON value, for
// any input and however the key is spelled (L173). au and bu are any sequences of UTF-16 code units,
// lone surrogates included, each written as an escape; raw and raw2 are any bytes written as they
// are, UTF-8 or not. A code-unit sequence is its own value. Raw bytes are the value of their
// characters when they are UTF-8, and of themselves otherwise. encoding/json's spellings of a valid
// sequence, with and without HTML escaping, share its key.
func FuzzIDKeyIsOneKeyPerValue(f *testing.F) {
	f.Add(unitBytes(0xd800), unitBytes(0xdc00), []byte{0xff}, []byte{0xfe})
	f.Add(unitBytes(0xd800), unitBytes([]uint16(utf16.Encode([]rune(`\ud800`)))...), []byte{0xed, 0xa0, 0x80}, []byte("\xef\xbf\xbd"))
	f.Add(unitBytes([]uint16(utf16.Encode([]rune(`\xff`)))...), unitBytes(0xfffd), []byte{0xff}, []byte("xff"))
	f.Add(unitBytes(0xd83d, 0xde00), unitBytes(0xdc00, 0xdc00), []byte("😀"), []byte("a<b&c"))
	f.Fuzz(func(t *testing.T, au, bu, raw, raw2 []byte) {
		a, b := codeUnits(au), codeUnits(bu)
		ka, kb := idKey(json.RawMessage(escapedUnits(a))), idKey(json.RawMessage(escapedUnits(b)))
		if (ka == kb) != slices.Equal(a, b) {
			t.Fatalf("code units %x and %x: keys %q and %q", a, b, ka, kb)
		}
		if r := utf16.Decode(a); slices.Equal(utf16.Encode(r), a) { // no lone surrogate: a string Go can hold
			for _, html := range []bool{true, false} {
				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetEscapeHTML(html)
				if err := enc.Encode(string(r)); err != nil {
					t.Fatal(err)
				}
				if k := idKey(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))); k != ka {
					t.Fatalf("code units %x: key %q written by encoding/json (HTML escaping %v), %q escaped", a, k, html, ka)
				}
			}
		}
		if !plainBytes(raw) || !plainBytes(raw2) {
			return
		}
		kr, kr2 := idKey(json.RawMessage(`"`+string(raw)+`"`)), idKey(json.RawMessage(`"`+string(raw2)+`"`))
		if (kr == kr2) != bytes.Equal(raw, raw2) {
			t.Fatalf("raw %x and %x: keys %q and %q", raw, raw2, kr, kr2)
		}
		if same := utf8.Valid(raw) && slices.Equal(utf16.Encode([]rune(string(raw))), a); (kr == ka) != same {
			t.Fatalf("raw %x and code units %x: keys %q and %q, one value %v", raw, a, kr, ka, same)
		}
	})
}

// codeUnits reads b as big-endian UTF-16 code units; an odd last byte is dropped.
func codeUnits(b []byte) []uint16 {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	return u
}

// unitBytes is the big-endian bytes of code units u, as codeUnits reads them.
func unitBytes(u ...uint16) []byte {
	b := make([]byte, 0, 2*len(u))
	for _, c := range u {
		b = binary.BigEndian.AppendUint16(b, c)
	}
	return b
}

// escapedUnits is a JSON string of code units u, each an escape in upper-case hex.
func escapedUnits(u []uint16) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, c := range u {
		fmt.Fprintf(&out, `\u%04X`, c)
	}
	out.WriteByte('"')
	return out.String()
}

// plainBytes reports whether b can stand unescaped inside a JSON string: no quote, backslash or
// control character (bytes that are not UTF-8 included).
func plainBytes(b []byte) bool {
	return !bytes.ContainsFunc(b, func(r rune) bool { return r == '"' || r == '\\' || r < 0x20 })
}

func TestScalarIDAcceptsStringsAndIntegersOnly(t *testing.T) {
	for raw, ok := range map[string]bool{`"a"`: true, `7`: true, `-3`: true, `1.5`: false, `1e3`: false, `true`: false, `null`: false} {
		if err := scalarID([]byte(raw)); (err == nil) != ok {
			t.Errorf("scalarID(%s) = %v", raw, err)
		}
	}
}

// fuzzPaths are every path the proxy rewrites or reads.
var fuzzPaths = []jsonPath{pathID, pathToken, pathLogLevel, pathVersion, pathProgress}

// FuzzLocateAndReplace: for any message locate accepts, each located value is the one at its path
// (as encoding/json reads the message), an absent path is absent, replacing the located values
// changes those paths and nothing else, and putting them back gives the message byte for byte.
func FuzzLocateAndReplace(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"progressToken":"p"},"name":"x"}}`,
		`{"id":"a","params":{"progressToken":"r","_meta":{"progressToken":3}},"x":{"id":5}}`,
		`{ "params" : { "_meta" : { "io.modelcontextprotocol/logLevel":"info" } } , "id" : -12 }`,
		`{"result":{"id":1},"id":"\u00e9","params":{"arguments":{"_meta":{"progressToken":9}}}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		at, err := locate(msg, fuzzPaths...)
		if err != nil {
			return
		}
		var tree any
		if err := json.Unmarshal(msg, &tree); err != nil {
			t.Fatalf("locate accepted %q, which encoding/json refuses: %v", msg, err)
		}
		var edits, restore []edit
		for i, s := range at {
			v, present := valueAt(tree, fuzzPaths[i])
			if (s != nil) != present {
				t.Fatalf("path %v: located %v, present %v in %q", fuzzPaths[i], s != nil, present, msg)
			}
			if s == nil {
				continue
			}
			var got any
			if err := json.Unmarshal(s.value(msg), &got); err != nil || !reflect.DeepEqual(got, v) {
				t.Fatalf("path %v: located %q, but the value there is %v", fuzzPaths[i], s.value(msg), v)
			}
			edits = append(edits, edit{s, []byte(fmt.Sprintf(`"byw-%d"`, i))})
			restore = append(restore, edit{s, bytes.Clone(s.value(msg))})
		}
		out := replace(msg, edits...)
		var outTree any
		if err := json.Unmarshal(out, &outTree); err != nil {
			t.Fatalf("rewriting %q gave invalid JSON %q", msg, out)
		}
		for i, s := range at {
			if s != nil {
				if v, _ := valueAt(outTree, fuzzPaths[i]); v != fmt.Sprintf("byw-%d", i) {
					t.Fatalf("path %v holds %v after rewriting, want its own replacement", fuzzPaths[i], v)
				}
				clearAt(tree, fuzzPaths[i])
				clearAt(outTree, fuzzPaths[i])
			}
		}
		if !reflect.DeepEqual(tree, outTree) {
			t.Fatalf("rewriting %q changed more than the targeted paths: %q", msg, out)
		}
		again, err := locate(out, fuzzPaths...)
		if err != nil {
			t.Fatalf("the rewritten message %q no longer locates: %v", out, err)
		}
		for i := range restore {
			restore[i].at = again[indexOf(at, restore[i].at)]
		}
		if back := replace(out, restore...); !bytes.Equal(back, msg) {
			t.Fatalf("round trip changed the message:\n%q\n%q", msg, back)
		}
	})
}

// valueAt follows path through decoded JSON objects.
func valueAt(tree any, path jsonPath) (any, bool) {
	for _, k := range path {
		m, ok := tree.(map[string]any)
		if !ok {
			return nil, false
		}
		if tree, ok = m[k]; !ok {
			return nil, false
		}
	}
	return tree, true
}

// clearAt deletes the value at path, so two trees can be compared without it.
func clearAt(tree any, path jsonPath) {
	parent, ok := valueAt(tree, path[:len(path)-1])
	if m, isMap := parent.(map[string]any); ok && isMap {
		delete(m, path[len(path)-1])
	}
}

func indexOf(spans []*span, s *span) int {
	for i, x := range spans {
		if x == s {
			return i
		}
	}
	return -1
}
