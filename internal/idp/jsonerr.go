package idp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// JSONError describes a JSON decoding error without quoting the input. encoding/json messages
// echo the offending bytes ("invalid character 'd' …"), which is a leak when an operator points a
// setting at a secret file by mistake (invariant 2). Only byte offsets remain.
func JSONError(err error) error {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return fmt.Errorf("not valid JSON at byte %d", se.Offset)
	case errors.As(err, &te):
		// Field is not reported: with Go's jsonv2 semantics it is built from the input's own key
		// names (map keys included), so it can carry input bytes.
		return fmt.Errorf("wrong JSON type at byte %d", te.Offset)
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return errors.New("not valid JSON: unexpected end of input")
	}
	return errors.New("not valid JSON")
}
