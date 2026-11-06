//go:build linux || darwin

package stdio

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
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
		"duplicate id":            `{"id":1,"method":"x","id":2}`,
		"duplicate params":        `{"id":1,"params":{},"params":{"_meta":{"progressToken":1}}}`,
		"duplicate progressToken": `{"id":1,"params":{"_meta":{"progressToken":1,"progressToken":2}}}`,
		"object id":               `{"id":{"a":1}}`,
		"object progressToken":    `{"id":1,"params":{"_meta":{"progressToken":{}}}}`,
		"array progressToken":     `{"id":1,"params":{"_meta":{"progressToken":[1]}}}`,
		"not an object":           `[{"id":1}]`,
		"malformed":               `{"id":1,`,
		"trailing data":           `{"id":1} {"id":2}`,
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

func TestScalarIDAcceptsStringsAndIntegersOnly(t *testing.T) {
	for raw, ok := range map[string]bool{`"a"`: true, `7`: true, `-3`: true, `1.5`: false, `1e3`: false, `true`: false, `null`: false} {
		if err := scalarID([]byte(raw)); (err == nil) != ok {
			t.Errorf("scalarID(%s) = %v", raw, err)
		}
	}
}

// FuzzLocateAndReplace: for any message locate accepts, replacing a located value and putting it
// back gives the message unchanged, and no byte outside the located spans ever changes.
func FuzzLocateAndReplace(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"progressToken":"p"},"name":"x"}}`,
		`{"id":"a","params":{"requestId":"r","_meta":{"progressToken":3}},"x":{"id":5}}`,
		`{ "params" : { "_meta" : { } } , "id" : -12 }`,
		`{"result":{"id":1},"id":"é"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		at, err := locate(msg, rewritePaths...)
		if err != nil {
			return
		}
		if !json.Valid(msg) {
			t.Fatalf("locate accepted invalid JSON %q", msg)
		}
		var edits, restore []edit
		for _, s := range at {
			if s == nil {
				continue
			}
			edits = append(edits, edit{s, []byte(`"byw-x"`)})
			restore = append(restore, edit{s, bytes.Clone(s.value(msg))})
		}
		out := replace(msg, edits...)
		if !json.Valid(out) {
			t.Fatalf("rewriting %q gave invalid JSON %q", msg, out)
		}
		again, err := locate(out, rewritePaths...)
		if err != nil {
			t.Fatalf("the rewritten message %q no longer locates: %v", out, err)
		}
		for i, s := range again {
			if (s == nil) != (at[i] == nil) || (s != nil && string(s.value(out)) != `"byw-x"`) {
				t.Fatalf("path %v moved after rewriting %q", rewritePaths[i], msg)
			}
		}
		for i := range restore {
			restore[i].at = again[indexOf(at, restore[i].at)]
		}
		if back := replace(out, restore...); !bytes.Equal(back, msg) {
			t.Fatalf("round trip changed the message:\n%q\n%q", msg, back)
		}
	})
}

func indexOf(spans []*span, s *span) int {
	for i, x := range spans {
		if x == s {
			return i
		}
	}
	return -1
}
