package idp

import (
	"encoding/base64"

	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
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
		"wrong type":   {`{"keys":"` + secretish + `"}`, "wrong JSON type at byte"},
		"map key path": {`{"deadbeefcafef00ddeadbeefcafef00d":{"keys":1}}`, "wrong JSON type at byte"},
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
			if !strings.Contains(got, tc.want) || strings.Contains(got, secretish[:4]) || strings.Contains(got, "deadbeef") {
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

var b64 = base64.RawURLEncoding

func TestMalformedJWTErrorsDoNotQuoteTheToken(t *testing.T) {
	const secretish = "dGhpcy1pcy1hLXNlY3JldA"
	for _, raw := range []string{
		b64.EncodeToString([]byte(`{"alg":"RS256",`+secretish)) + ".e30.sig",
		secretish + "." + secretish + "." + secretish,
		b64.EncodeToString([]byte(`{"alg":"`+secretish+`"}`)) + ".e30.sig",
	} {
		_, err := VerifySignature(context.Background(), raw, StaticKeys{}, []jose.SignatureAlgorithm{jose.RS256})
		if err == nil || strings.Contains(err.Error(), secretish[:4]) || strings.Contains(err.Error(), "'") {
			t.Fatalf("VerifySignature(%q) = %v", raw[:12], err)
		}
	}
}
