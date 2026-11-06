package idp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestJSONErrorIsContentFree(t *testing.T) {
	const secretish = "dGhpcy1pcy1hLXNlY3JldA"
	var v struct {
		Keys []string `json:"keys"`
	}
	for name, tc := range map[string]struct {
		input string
		want  string
	}{
		"syntax":       {secretish, "not valid JSON at byte 1"},
		"truncated":    {`{"keys":["` + secretish, "not valid JSON at byte"},
		"wrong type":   {`{"keys":"` + secretish + `"}`, "wrong JSON type for field keys"},
		"map key path": {`{"` + secretish + `":{"keys":1}}`, "wrong JSON type"},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			if name == "map key path" {
				var m map[string]struct {
					Keys []string `json:"keys"`
				}
				err = json.Unmarshal([]byte(tc.input), &m)
			} else {
				err = json.Unmarshal([]byte(tc.input), &v)
			}
			got := JSONError(err).Error()
			if !strings.Contains(got, tc.want) || strings.Contains(got, secretish[:4]) {
				t.Fatalf("JSONError = %q, want %q without input", got, tc.want)
			}
		})
	}
	if JSONError(errors.New("other")).Error() != "not valid JSON" {
		t.Error("unknown error type not generic")
	}
}

func TestFetcherAndJWKSErrorsAreContentFree(t *testing.T) {
	const secretish = "dGhpcy1pcy1hLXNlY3JldA"
	if _, err := ParseJWKS([]byte(secretish)); err == nil || strings.Contains(err.Error(), secretish[:4]) || strings.Contains(err.Error(), "'d'") {
		t.Fatalf("ParseJWKS: %v", err)
	}
	var v map[string]any
	err := memoryFetcher(200, secretish).GetJSON(context.Background(), "https://idp.example/x", &v)
	if err == nil || strings.Contains(err.Error(), secretish[:4]) || strings.Contains(err.Error(), "'d'") {
		t.Fatalf("GetJSON: %v", err)
	}
}
