package broker

import (
	"net/http"
	"net/url"
	"regexp"

	"github.com/byward-dev/byward/internal/logging"
)

// oauthErrorCode is the shape of an OAuth error code; anything else from the query is not logged.
var oauthErrorCode = regexp.MustCompile(`^[a-z_]{1,64}$`)

// adminConsent answers the IdP's redirect after an administrator granted (or did not grant) our
// app the downstream API's permissions from the admin-consent URL (ADR-0017 §5). The redirect is
// unauthenticated and unverifiable: anyone can send one. So it only shows a page and logs at
// info; it writes no audit event, changes nothing (errors are never cached, so the next request
// simply retries), and never reads the returned tenant. Entra's error redirect carries
// admin_consent=True too, so error decides. The /callback rate limit covers it.
func (b *Broker) adminConsent(w http.ResponseWriter, r *http.Request, q url.Values) {
	ctx := r.Context()
	outcome := "granted"
	if e := q.Get("error"); e != "" {
		outcome = "error"
		if oauthErrorCode.MatchString(e) {
			outcome = "error " + e
		}
	}
	b.cfg.Log.InfoContext(ctx, "admin consent redirect received (unverified)", "request_id", logging.RequestID(ctx), "reason", outcome)
	if outcome != "granted" {
		b.page(w, r, http.StatusBadRequest, "Administrator consent was not granted",
			"The permissions were not granted. Try again from the link in the proxy's log, and check the permissions the app asks for.")
		return
	}
	b.page(w, r, http.StatusOK, "Administrator consent recorded",
		"If you granted the permissions, the app's tools that need them work from the next request. You can close this page.")
}
