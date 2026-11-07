package idp

import (
	"errors"
	"fmt"
	"strings"
)

// Class says what the broker should do about an IdP error (ADR-0011 §1).
type Class int

// Error classes.
const (
	// Fatal: the request cannot succeed (bad configuration, protocol violation).
	Fatal Class = iota
	// SignInAgain: the user must log in again (expired or revoked grant, consent, MFA).
	SignInAgain
	// Unavailable: try later. Includes invalid_client, so a broken credential never signs
	// everyone out.
	Unavailable
)

func (c Class) String() string {
	switch c {
	case SignInAgain:
		return "sign_in_again"
	case Unavailable:
		return "unavailable"
	}
	return "fatal"
}

// Error is an IdP failure. Error() never includes the IdP's error_description, which may carry
// user identifiers; Description is kept for operator logs only.
// ErrCredential wraps a ClientAuth that could not make its credential, such as an unreadable or
// empty client assertion file: the request never left the proxy.
var ErrCredential = errors.New("idp: the client credential could not be made")

type Error struct {
	Class Class
	// OAuth is the RFC 6749 error value, if the IdP sent one.
	OAuth string
	// Code is the IdP's own error code (Entra AADSTS number), 0 if none.
	Code int
	// Status is the HTTP status of the token response, 0 for callback errors.
	Status        int
	TraceID       string
	CorrelationID string
	// Alert asks for a loud operator alert (e.g. the IdP rejects our credential).
	Alert bool
	// UserMessage is safe to show on an error page and may be empty (the caller supplies a
	// default); OperatorHint names the fix.
	UserMessage  string
	OperatorHint string
	Description  string
	Err          error
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "idp: %s", e.Class)
	if e.OAuth != "" {
		fmt.Fprintf(&b, " error=%s", e.OAuth)
	}
	if e.Code != 0 {
		fmt.Fprintf(&b, " code=%d", e.Code)
	}
	if e.Status != 0 {
		fmt.Fprintf(&b, " status=%d", e.Status)
	}
	if e.TraceID != "" {
		fmt.Fprintf(&b, " trace_id=%s", e.TraceID)
	}
	if e.CorrelationID != "" {
		fmt.Fprintf(&b, " correlation_id=%s", e.CorrelationID)
	}
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// ClassOf returns the class of err, Fatal if err is not an *Error.
func ClassOf(err error) Class {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return Fatal
}

// GenericClass classes an RFC 6749 token error from any IdP.
func GenericClass(status int, oauth string) Class {
	switch {
	case status >= 500 || status == 429 || oauth == "temporarily_unavailable" || oauth == "server_error":
		return Unavailable
	case oauth == "invalid_client":
		return Unavailable
	case oauth == "invalid_grant" || oauth == "interaction_required" || oauth == "login_required" || oauth == "consent_required":
		// Re-authentication can fix these.
		return SignInAgain
	}
	return Fatal
}

// TokenCheckError wraps a failure to verify an IdP-signed JWT. It is Unavailable when the IdP's
// keys could not be fetched (try later), and Fatal for anything else (bad signature or claims), in
// which case hint, the operator's fix for a misconfiguration, is kept.
func TokenCheckError(err error, hint string) *Error {
	if errors.Is(err, ErrKeysUnavailable) {
		return &Error{Class: Unavailable, Err: err}
	}
	return &Error{Class: Fatal, OperatorHint: hint, Err: err}
}
