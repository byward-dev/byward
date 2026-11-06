package idp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// fieldPath matches the struct paths encoding/json reports for our own types; anything else could
// come from the input and is left out.
var fieldPath = regexp.MustCompile(`^[a-z0-9_.]{1,64}$`)

// JSONError describes a JSON decoding error without quoting the input. encoding/json messages
// echo the offending bytes ("invalid character 'd' …"), which is a leak when an operator points a
// setting at a secret file by mistake (invariant 2). Only offsets and our own field names remain.
func JSONError(err error) error {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return fmt.Errorf("not valid JSON at byte %d", se.Offset)
	case errors.As(err, &te):
		if fieldPath.MatchString(te.Field) {
			return fmt.Errorf("wrong JSON type for field %s at byte %d", te.Field, te.Offset)
		}
		return fmt.Errorf("wrong JSON type at byte %d", te.Offset)
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return errors.New("not valid JSON: unexpected end of input")
	}
	return errors.New("not valid JSON")
}
