package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/ratelimit"
	"github.com/byward-dev/byward/internal/registration"
)

// Registrar registers clients dynamically (RFC 7591, ADR-0008 §2-3).
type Registrar interface {
	Register(ctx context.Context, body []byte) (*registration.Registered, error)
}

// Registration outcomes, for metrics and the audit reason (fixed values).
const (
	RegistrationOK          = "registered"
	RegistrationBadRedirect = "invalid_redirect_uri"
	RegistrationBadMetadata = "invalid_client_metadata"
	RegistrationFull        = "full"
	RegistrationUnavailable = "unavailable"
	RegistrationRateLimited = "rate_limited"
)

// registrationRetryAfter is the Retry-After for a 503 from /register (full, or the store down).
const registrationRetryAfter = "60"

// register is POST /register (RFC 7591). The sender is not authenticated, so every outcome is
// audited rate-limited per source and counted; consent is still asked for every DCR client
// (MCP security considerations: dynamically registered clients).
func (b *Broker) register(w http.ResponseWriter, r *http.Request) {
	cors(w, r, "POST, OPTIONS")
	switch r.Method {
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if retry, limited := b.throttled(w, r, ratelimit.Register); limited {
		b.registrationFailed(w, r, RegistrationRateLimited, http.StatusTooManyRequests, "temporarily_unavailable",
			"too many registrations from this address; retry after "+strconv.Itoa(retry)+" s")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		b.registrationFailed(w, r, RegistrationBadMetadata, http.StatusBadRequest, "invalid_client_metadata", "the request must be JSON (application/json)")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		b.registrationFailed(w, r, RegistrationBadMetadata, http.StatusBadRequest, "invalid_client_metadata", "the request body could not be read")
		return
	}
	reg, err := b.cfg.Registrar.Register(r.Context(), body)
	switch {
	case errors.Is(err, registration.ErrInvalidRedirectURI):
		b.registrationFailed(w, r, RegistrationBadRedirect, http.StatusBadRequest, "invalid_redirect_uri", firstLine(err))
		return
	case errors.Is(err, registration.ErrInvalidClientMetadata):
		b.registrationFailed(w, r, RegistrationBadMetadata, http.StatusBadRequest, "invalid_client_metadata", firstLine(err))
		return
	case errors.Is(err, registration.ErrRegistrationsFull):
		w.Header().Set("Retry-After", registrationRetryAfter)
		b.registrationFailed(w, r, RegistrationFull, http.StatusServiceUnavailable, "temporarily_unavailable", "the proxy is not accepting new registrations now")
		return
	case err != nil:
		b.cfg.Log.ErrorContext(r.Context(), "registering a client failed", "request_id", logging.RequestID(r.Context()), "error", err.Error())
		w.Header().Set("Retry-After", registrationRetryAfter)
		b.registrationFailed(w, r, RegistrationUnavailable, http.StatusServiceUnavailable, "temporarily_unavailable", "the proxy could not store the registration")
		return
	}
	if len(reg.Dropped) > 0 {
		// RFC 7591 §3.2.2 lets the server substitute values; the dropped URIs are not an error.
		b.cfg.Log.InfoContext(r.Context(), "client registration dropped redirect URIs", "request_id", logging.RequestID(r.Context()),
			"client_id", reg.ClientID, "reason", "fail the redirect policy (ADR-0009): "+strings.Join(reg.Dropped, ", "))
	}
	b.cfg.Audit.RecordUnauthenticated(r, audit.Event{Name: audit.ClientRegistered, Outcome: audit.Success, Reason: "dcr", ClientID: reg.ClientID})
	b.observeRegistration(RegistrationOK)
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(reg.Response)
}

// registrationFailed answers RFC 7591 §3.2.2 JSON, audits the refusal (rate-limited per source)
// and counts it.
func (b *Broker) registrationFailed(w http.ResponseWriter, r *http.Request, outcome string, status int, code, desc string) {
	b.cfg.Audit.RecordUnauthenticated(r, audit.Event{Name: audit.ClientRegistered, Outcome: audit.Failure, Reason: outcome})
	b.observeRegistration(outcome)
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code,
		"error_description": desc + " (reference " + logging.RequestID(r.Context()) + ")"})
}

func (b *Broker) observeRegistration(outcome string) {
	if b.cfg.ObserveRegistration != nil {
		b.cfg.ObserveRegistration(outcome)
	}
}

// firstLine is the reason after the error's class, for error_description: the metadata rule
// that failed, never request data beyond the field name.
func firstLine(err error) string {
	s := err.Error()
	if i := strings.Index(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
