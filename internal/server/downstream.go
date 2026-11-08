package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/downstream"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/upstream/relay"
	"github.com/byward-dev/byward/internal/upstream/stdio"
)

// downstreamTokens is On-Behalf-Of (ADR-0017): a token for the downstream API, exchanged for the
// signed-in user's stored IdP token and cached. Every request to an HTTP upstream carries it in
// its own header; a stdio upstream process asks its token socket for it (forProcess), after the
// same check in front of every request has made sure there is one.
type downstreamTokens struct {
	cache    *downstream.Cache
	header   string
	resource string // the downstream API, for messages
	// assertion returns the grant's stored IdP access token and its expiry.
	assertion func(ctx context.Context, grantID string) (string, time.Time, error)
	// consentURL is where an administrator of a tenant grants the scopes.
	consentURL func(tenantID string) string
	idp        string
	log        *slog.Logger
	o          Observability
	now        func() time.Time
}

func newDownstreamTokens(scopes []string, header string, provider *entra.Provider, idpName string, assertion func(context.Context, string) (string, time.Time, error),
	log *slog.Logger, o Observability) *downstreamTokens {
	exchange := func(ctx context.Context, tid, assertion string, scopes []string) (downstream.Token, error) {
		t, err := provider.OnBehalfOf(idp.WithRequestID(ctx, logging.RequestID(ctx)), tid, assertion, scopes)
		return downstream.Token{AccessToken: t.AccessToken, ExpiresAt: t.ExpiresAt}, err
	}
	res := scopes[0][:strings.LastIndex(scopes[0], "/")]
	return &downstreamTokens{cache: downstream.New(exchange, scopes, 0, time.Now), header: header, resource: res,
		assertion: assertion, consentURL: func(tid string) string { return provider.AdminConsentURL(tid, scopes) },
		idp: idpName, log: log, o: o, now: time.Now}
}

// downstreamKey carries a request's downstream token from middleware to the relay.
type downstreamKey struct{}

// inject sets the downstream token on the upstream request, after the inbound copies are gone.
func (d *downstreamTokens) inject(ctx context.Context, h http.Header) {
	if tok, ok := ctx.Value(downstreamKey{}).(string); ok {
		h.Set(d.header, "Bearer "+tok)
	}
}

// middleware gets the user's downstream token before the request is relayed. A request it cannot
// get one for is answered in the proxy's name (ADR-0025 shapes, ADR-0017 §5) and never reaches the
// upstream.
func (d *downstreamTokens) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := resource.IdentityFrom(r.Context())
		d.serve(w, r, id, ok, next)
	})
}

// serve relays r with the downstream token of id, the identity the guard attached (ok), or refuses.
func (d *downstreamTokens) serve(w http.ResponseWriter, r *http.Request, id resource.Identity, ok bool, next http.Handler) {
	ctx := r.Context()
	if ok && id.PrincipalType == resource.PrincipalClient {
		// An app-only caller (ADR-0022) acts for no user, so there is no one to act on behalf of: it is
		// relayed without a downstream token, and the assertion's principal_type tells the upstream.
		next.ServeHTTP(w, r)
		return
	}
	tid, oid, keyed := strings.Cut(id.Subject, ":")
	if !ok || !keyed || id.GrantID == "" {
		d.refuse(w, r, id, "failed", errors.New("no signed-in Entra user for the request"))
		return
	}
	assertion, expires, err := d.assertion(ctx, id.GrantID)
	if err != nil {
		d.refuse(w, r, id, "failed", err)
		return
	}
	tok, cached, err := d.cache.Token(ctx, downstream.User{TenantID: tid, ObjectID: oid, Assertion: assertion, AssertionExpiresAt: expires})
	if err != nil && ctx.Err() != nil {
		return // the client went away while waiting: nothing was refused and no one is left to answer
	}
	if err != nil {
		d.refuse(w, r, id, outcomeOf(err), err)
		return
	}
	if cached {
		d.o.Metrics.Downstream("cached")
	} else {
		d.o.Metrics.Downstream("issued")
	}
	next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, downstreamKey{}, tok.AccessToken)))
}

// outcomeOf names an exchange error: the two Entra answers ADR-0017 §5 singles out, an IdP that
// is unavailable, or anything else.
func outcomeOf(err error) string {
	var ie *idp.Error
	switch {
	case errors.As(err, &ie) && ie.Code == entra.CodeConsentRequired:
		return "consent_required"
	case errors.As(err, &ie) && ie.OAuth == entra.OAuthInteractionNeeded:
		return "interaction_required"
	case idp.ClassOf(err) == idp.Unavailable:
		return "unavailable"
	}
	return "failed"
}

// refuse answers a request without a downstream token, alerts the operator and records it.
func (d *downstreamTokens) refuse(w http.ResponseWriter, r *http.Request, id resource.Identity, outcome string, err error) {
	d.record(r.Context(), r, id, outcome, err)
	relay.Answer(w, r, refusalMessage(outcome, d.resource), map[string]string{"downstream": outcome}, http.StatusServiceUnavailable)
}

// record alerts the operator to a refused token and records it: the metric, the audit record (for
// request r, nil for a stdio process's own ask) and the error log, with the admin-consent URL when
// consent is missing.
func (d *downstreamTokens) record(ctx context.Context, r *http.Request, id resource.Identity, outcome string, err error) {
	d.o.Metrics.Downstream(outcome)
	d.o.Audit.Record(r, audit.Event{Name: audit.DownstreamTokenRefused, Outcome: audit.Failure, Reason: outcome,
		ClientID: id.ClientID, UserKey: id.Subject, GrantID: id.GrantID, IdP: d.idp})
	reason := outcome
	var ie *idp.Error
	isIdP := errors.As(err, &ie)
	if isIdP && ie.OperatorHint != "" {
		reason = outcome + ": " + ie.OperatorHint
	}
	attrs := []any{"request_id", logging.RequestID(ctx), "reason", reason, "error", err}
	if isIdP {
		// The IdP's error code and its own trace IDs; never its error_description (ADR-0021 §7).
		attrs = append(attrs, "idp_error_code", ie.Code, "trace_id", ie.TraceID, "correlation_id", ie.CorrelationID)
	}
	if outcome == "consent_required" {
		tid, _, _ := strings.Cut(id.Subject, ":")
		attrs = append(attrs, "admin_consent_url", d.consentURL(tid))
	}
	if r == nil {
		d.log.ErrorContext(ctx, "no downstream token for a stdio process's ask on its token socket", attrs...)
		return
	}
	d.log.ErrorContext(ctx, "no downstream token for the upstream request; answered in the proxy's name", attrs...)
}

// forProcess is the downstream token a stdio upstream process asks its token socket for: for its
// user, exchanged for the stored IdP token of the grant whose request it served last. A refusal
// is alerted and recorded as for a request; the process gets only the outcome. An app-only caller
// acts for no user (no_user). A grant whose stored token or own lifetime has ended, or that was
// revoked or signed out since, waits for the client's next request (sign_in_expired): byward never
// refreshes IdP tokens outside a request.
func (d *downstreamTokens) forProcess(ctx context.Context, p stdio.Identity) stdio.DownstreamToken {
	id := resource.Identity{Subject: p.Subject, PrincipalType: p.PrincipalType, GrantID: p.Grant, ClientID: p.Client}
	tid, oid, keyed := strings.Cut(id.Subject, ":")
	if id.PrincipalType == resource.PrincipalClient || !keyed || id.GrantID == "" {
		d.o.Metrics.Downstream("no_user")
		return stdio.DownstreamToken{Error: "no_user"}
	}
	assertion, expires, err := d.assertion(ctx, id.GrantID)
	if errors.Is(err, store.ErrNotFound) {
		// Signed out or revoked since its last request (revocation deletes the grant): routine, not
		// a refusal to alert on; the user's next request, under a new grant, brings a new token.
		d.o.Metrics.Downstream("sign_in_expired")
		return stdio.DownstreamToken{Error: "sign_in_expired"}
	}
	if err != nil {
		d.record(ctx, nil, id, "failed", err)
		return stdio.DownstreamToken{Error: "failed"}
	}
	if !expires.IsZero() && !d.now().Before(expires) {
		d.o.Metrics.Downstream("sign_in_expired")
		return stdio.DownstreamToken{Error: "sign_in_expired"}
	}
	tok, cached, err := d.cache.Token(ctx, downstream.User{TenantID: tid, ObjectID: oid, Assertion: assertion, AssertionExpiresAt: expires})
	if err != nil {
		outcome := outcomeOf(err)
		d.record(ctx, nil, id, outcome, err)
		return stdio.DownstreamToken{Error: outcome}
	}
	if cached {
		d.o.Metrics.Downstream("cached")
	} else {
		d.o.Metrics.Downstream("issued")
	}
	return stdio.DownstreamToken{AccessToken: tok.AccessToken, ExpiresAt: tok.ExpiresAt}
}

// refusalMessage is what the client is told for a refusal outcome; it names the downstream API and
// never the IdP's error.
func refusalMessage(outcome, api string) string {
	if !strings.Contains(api, "://") { // an API addressed by its app ID (#196): say what the GUID is
		api = "the application " + api
	}
	switch outcome {
	case "consent_required":
		return "This tool needs an administrator to grant access to " + api + ". Ask your operator."
	case "interaction_required":
		return "Your organisation's access policy requires a step for " + api + " that this app cannot complete. Ask your operator."
	case "unavailable":
		return "The sign-in service is temporarily unavailable. Try again shortly."
	}
	return "The proxy could not get access to " + api + " on your behalf. Ask your operator."
}
