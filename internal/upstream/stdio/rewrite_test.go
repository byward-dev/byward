//go:build linux || darwin

package stdio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
