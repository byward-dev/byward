package idp

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
)

// CallbackResult is the parsed IdP redirect: either a code or an error response.
type CallbackResult struct {
	Code             string
	Error            string
	ErrorDescription string
}

// ReadCallback checks state and, when the IdP advertises RFC 9207, `iss` (ADR-0011 §6), and returns
// the code or the IdP's error. wantIss is "" when the IdP does not send `iss`.
func ReadCallback(q url.Values, l Login, wantIss string) (CallbackResult, error) {
	if l.State == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(l.State)) != 1 {
		return CallbackResult{}, errors.New("idp: callback state mismatch")
	}
	if wantIss != "" && q.Get("iss") != wantIss {
		return CallbackResult{}, errors.New("idp: callback iss mismatch")
	}
	if e := q.Get("error"); e != "" {
		return CallbackResult{Error: e, ErrorDescription: q.Get("error_description")}, nil
	}
	code := q.Get("code")
	if code == "" {
		return CallbackResult{}, errors.New("idp: callback has neither code nor error")
	}
	return CallbackResult{Code: code}, nil
}

// CodeChallenge is the PKCE S256 challenge for verifier.
func CodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
