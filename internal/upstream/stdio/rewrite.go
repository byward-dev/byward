//go:build linux || darwin

package stdio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
)

// jsonPath is a path of object keys from the root of a JSON-RPC message.
type jsonPath []string

// span is where a scalar value sits in a message: msg[start:end].
type span struct{ start, end int }

// errAmbiguous is returned for a message whose targeted values cannot be found with certainty:
// malformed JSON, trailing data, a key repeated in an object on the way to a targeted path, or a
// targeted value that is an object or array. Such a message is refused, never guessed at: guessing
// could route one client's data to another (ADR-0003 §4).
var errAmbiguous = errors.New("stdio: ambiguous JSON-RPC message")

// locate walks msg, which must be one JSON object, and returns where each path's value is: nil for
// a path that is not present.
func locate(msg []byte, paths ...jsonPath) ([]*span, error) {
	type frame struct {
		object    bool
		expectKey bool
		key       string
		path      jsonPath // set when this object is on the way to a targeted path
		seen      map[string]bool
	}
	onWay := func(p jsonPath) bool {
		for _, t := range paths {
			if len(p) < len(t) && slices.Equal(t[:len(p)], p) {
				return true
			}
		}
		return false
	}
	target := func(p jsonPath) int {
		for i, t := range paths {
			if slices.Equal(t, p) {
				return i
			}
		}
		return -1
	}
	found := make([]*span, len(paths))
	dec := json.NewDecoder(bytes.NewReader(msg))
	dec.UseNumber()
	var stack []*frame
	done := false
	for {
		prev := int(dec.InputOffset())
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || done {
			return nil, errAmbiguous // malformed, or data after the message
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		} else if d, ok := tok.(json.Delim); !ok || d != '{' {
			return nil, errAmbiguous // a message is one object
		}
		if top != nil && top.object && top.expectKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				done = len(stack) == 0
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expectKey = true
				}
				continue
			}
			key, _ := tok.(string)
			if top.path != nil {
				if top.seen[key] {
					return nil, errAmbiguous
				}
				top.seen[key] = true
			}
			top.key, top.expectKey = key, false
			continue
		}
		var at jsonPath // the path of this value, if its parent is on the way to a target
		if top != nil && top.object && top.path != nil {
			at = append(slices.Clone(top.path), top.key)
		}
		switch d, _ := tok.(json.Delim); d {
		case '{', '[':
			if at != nil && target(at) >= 0 {
				return nil, errAmbiguous // targeted values are scalars
			}
			f := &frame{object: d == '{', expectKey: d == '{'}
			if top == nil {
				f.path, f.seen = jsonPath{}, map[string]bool{}
			} else if d == '{' && at != nil && onWay(at) {
				f.path, f.seen = at, map[string]bool{}
			}
			stack = append(stack, f)
			continue
		case '}', ']':
			stack = stack[:len(stack)-1]
			done = len(stack) == 0
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
			continue
		}
		if at != nil {
			if i := target(at); i >= 0 {
				start := prev
				for start < len(msg) && bytes.IndexByte([]byte(" \t\r\n:,"), msg[start]) >= 0 {
					start++
				}
				found[i] = &span{start: start, end: int(dec.InputOffset())}
			}
		}
		if top.object {
			top.expectKey = true
		}
	}
	if !done {
		return nil, errAmbiguous
	}
	return found, nil
}

// edit is one replacement of a located value.
type edit struct {
	at  *span
	val []byte
}

// replace returns msg with each edit's span replaced by its value; spans must not overlap. Every
// other byte is kept, so key order, unknown keys and spacing survive.
func replace(msg []byte, edits ...edit) []byte {
	var es []edit
	for _, e := range edits {
		if e.at != nil {
			es = append(es, e)
		}
	}
	sort.Slice(es, func(i, j int) bool { return es[i].at.start < es[j].at.start })
	out := make([]byte, 0, len(msg))
	last := 0
	for _, e := range es {
		out = append(out, msg[last:e.at.start]...)
		out = append(out, e.val...)
		last = e.at.end
	}
	return append(out, msg[last:]...)
}

// value returns the bytes at s in msg.
func (s *span) value(msg []byte) []byte { return msg[s.start:s.end] }

// scalarID checks a located id or progress token: a JSON string or integer (MCP basic, Requests;
// progress). Anything else is refused.
func scalarID(raw []byte) error {
	if len(raw) == 0 || !validID(raw) {
		return fmt.Errorf("%w: %s must be a string or an integer", errAmbiguous, raw)
	}
	return nil
}
