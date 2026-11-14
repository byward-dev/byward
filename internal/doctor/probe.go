package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Target is what the self-probe expects, from the proxy's configuration.
type Target struct {
	// Resource is the public MCP URL exactly as users enter it.
	Resource *url.URL
	// Issuer is the broker's issuer.
	Issuer string
	// HostsSetting names the setting that lists extra accepted Host values, for the fix.
	HostsSetting string
	// AssertionKeyID is the key that signs identity assertions (an HTTP upstream); "" when there is
	// no assertion, and the discovery check is skipped.
	AssertionKeyID string
}

// maxMetadata bounds a metadata response (the 64 KB budget in docs/quality-lenses.md).
const maxMetadata = 64 << 10

// protocolVersion is sent on metadata requests, as the TypeScript SDK does (ADR-0013).
const protocolVersion = "2025-11-25"

const wellKnownResource = "/.well-known/oauth-protected-resource"

// SelfProbe fetches the proxy's metadata the way MCP clients do (ADR-0013 §8): protected resource
// metadata at the path-inserted and then the root URI (redirects are not followed), both authorization-server metadata
// documents, and an unauthenticated POST whose 401 must point at metadata that resolves. The URLs
// are built from the target here, as a client builds them, not taken from the proxy's code.
func SelfProbe(ctx context.Context, client *http.Client, t Target) []Result {
	// Redirects are reported, never followed: clients expect each document at its exact URL.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p := prober{ctx: ctx, client: &c, t: t}
	origin := t.Resource.Scheme + "://" + t.Resource.Host
	pathInserted := origin + wellKnownResource + t.Resource.Path
	out := []Result{
		p.resourceMetadata(CheckResourceMetadataPath, pathInserted),
		p.resourceMetadata(CheckResourceMetadataRoot, origin+wellKnownResource),
		p.serverMetadata(CheckServerMetadataRFC8414, strings.TrimSuffix(t.Issuer, "/")+"/.well-known/oauth-authorization-server"),
		p.serverMetadata(CheckServerMetadataOpenID, strings.TrimSuffix(t.Issuer, "/")+"/.well-known/openid-configuration"),
		p.challenge(pathInserted, origin+wellKnownResource),
	}
	if t.AssertionKeyID != "" {
		out = append(out, p.assertionKeys(strings.TrimSuffix(t.Issuer, "/")+"/.well-known/openid-configuration"))
	}
	return append(out, p.host())
}

type prober struct {
	ctx      context.Context
	client   *http.Client
	t        Target
	answered bool // some request got a response
	misdHost bool // a response was 421: the proxy did not accept the Host it was sent
}

// response is a fetched document; err is set when there was none worth reading.
type response struct {
	status int
	header http.Header
	body   []byte
	err    error
}

func (p *prober) do(method, target string, body io.Reader, header http.Header) response {
	req, err := http.NewRequestWithContext(p.ctx, method, target, body)
	if err != nil {
		return response{err: err}
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return response{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	p.answered = true
	p.misdHost = p.misdHost || resp.StatusCode == http.StatusMisdirectedRequest
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadata+1))
	if err != nil {
		return response{status: resp.StatusCode, err: err}
	}
	if len(b) > maxMetadata {
		return response{status: resp.StatusCode, err: fmt.Errorf("response is larger than %d bytes", maxMetadata)}
	}
	return response{status: resp.StatusCode, header: resp.Header, body: b}
}

// unreachable is the result for a request that got no response.
func (p *prober) unreachable(name Check, target string, err error) Result {
	return name.Result(Fail, "cannot reach "+target+": "+err.Error(), "start the proxy, and check that the public URL's host resolves to it from where doctor runs")
}

// unexpected is the result for a response with the wrong status.
func (p *prober) unexpected(name Check, target string, r response, want int) Result {
	res := name.Result(Fail, fmt.Sprintf("%s answered %d, want %d", target, r.status, want), "")
	switch {
	case r.status == http.StatusMisdirectedRequest:
		res.Fix = "the proxy refused the Host header (421): make the reverse proxy in front of it forward the original Host, or add the Host it sends to " + p.t.HostsSetting
	case r.status >= 300 && r.status < 400:
		res.Message += " (redirect to " + r.header.Get("Location") + ")"
		res.Fix = "make whatever is in front of the proxy pass this path through unchanged; clients expect the document at this exact URL"
	case r.status == http.StatusNotFound:
		res.Fix = "route /.well-known/ on this host to the proxy; it is served by the proxy, not by the upstream"
	default:
		res.Fix = "check the proxy's log and whatever is in front of it for this request"
	}
	return res
}

func (p *prober) resourceMetadata(name Check, target string) Result {
	r := p.do(http.MethodGet, target, nil, http.Header{"Mcp-Protocol-Version": {protocolVersion}})
	switch {
	case r.err != nil && r.status == 0:
		return p.unreachable(name, target, r.err)
	case r.err != nil:
		return name.Result(Fail, target+": "+r.err.Error(), "make whatever is in front of the proxy pass this path through unchanged; the proxy's own document is small")
	case r.status != http.StatusOK:
		return p.unexpected(name, target, r, http.StatusOK)
	}
	var doc struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(r.body, &doc); err != nil {
		return name.Result(Fail, target+" is not JSON: "+err.Error(), "make whatever is in front of the proxy pass this path through unchanged")
	}
	want := p.t.Resource.String()
	switch {
	case doc.Resource != want:
		// RFC 9728 §3.3: a client must not use metadata whose resource differs.
		return name.Result(Fail, fmt.Sprintf("resource is %q, want %q; clients reject this metadata", doc.Resource, want), "set the public URL to the URL users enter, and make sure this host reaches this proxy")
	case len(doc.AuthorizationServers) == 0 || doc.AuthorizationServers[0] != p.t.Issuer:
		// Claude uses the first entry and does not fall back (ADR-0013).
		return name.Result(Fail, fmt.Sprintf("authorization_servers is %q, want %q first", doc.AuthorizationServers, p.t.Issuer), "make sure this host reaches this proxy and not another deployment")
	}
	return name.Result(Pass, target+" names resource "+want+" and issuer "+p.t.Issuer, "")
}

func (p *prober) serverMetadata(name Check, target string) Result {
	r := p.do(http.MethodGet, target, nil, http.Header{"Mcp-Protocol-Version": {protocolVersion}})
	switch {
	case r.err != nil && r.status == 0:
		return p.unreachable(name, target, r.err)
	case r.err != nil:
		return name.Result(Fail, target+": "+r.err.Error(), "make whatever is in front of the proxy pass this path through unchanged; the proxy's own document is small")
	case r.status != http.StatusOK:
		return p.unexpected(name, target, r, http.StatusOK)
	}
	var doc struct {
		Issuer             string   `json:"issuer"`
		IssParameter       bool     `json:"authorization_response_iss_parameter_supported"`
		CodeChallenge      []string `json:"code_challenge_methods_supported"`
		RevocationEndpoint string   `json:"revocation_endpoint"`
	}
	if err := json.Unmarshal(r.body, &doc); err != nil {
		return name.Result(Fail, target+" is not JSON: "+err.Error(), "make whatever is in front of the proxy pass this path through unchanged")
	}
	var problems []string
	if doc.Issuer != p.t.Issuer {
		// RFC 8414 §3.3: a client must not use metadata whose issuer differs.
		problems = append(problems, fmt.Sprintf("issuer is %q, want %q, so clients reject this metadata", doc.Issuer, p.t.Issuer))
	}
	if !doc.IssParameter {
		problems = append(problems, "authorization_response_iss_parameter_supported is not true")
	}
	if !slices.Contains(doc.CodeChallenge, "S256") {
		problems = append(problems, "code_challenge_methods_supported lacks S256")
	}
	if doc.RevocationEndpoint == "" {
		problems = append(problems, "revocation_endpoint is missing")
	}
	if len(problems) > 0 {
		return name.Result(Fail, strings.Join(problems, "; "), "make sure this host reaches this proxy and not another server")
	}
	return name.Result(Pass, target+" names issuer "+p.t.Issuer, "")
}

var resourceMetadataParam = regexp.MustCompile(`resource_metadata="([^"]*)"`)

// challenge sends an MCP request without a token: the 401 must carry resource_metadata, and that
// URL must resolve to this resource's metadata (ADR-0013 §5, §8).
func (p *prober) challenge(accepted ...string) Result {
	name := CheckUnauthenticatedRequest
	target := p.t.Resource.String()
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	r := p.do(http.MethodPost, target, body, http.Header{
		"Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"},
		"Mcp-Protocol-Version": {protocolVersion},
	})
	switch {
	case r.err != nil && r.status == 0:
		return p.unreachable(name, target, r.err)
	case r.status != http.StatusUnauthorized:
		res := p.unexpected(name, target, r, http.StatusUnauthorized)
		if r.status >= 200 && r.status < 300 {
			res.Fix = "the request reached an MCP server without a token: make sure the public URL reaches the proxy and not the upstream directly"
		}
		return res
	}
	m := resourceMetadataParam.FindStringSubmatch(r.header.Get("WWW-Authenticate"))
	if m == nil {
		return name.Result(Fail, "the 401 has no resource_metadata in WWW-Authenticate", "make whatever is in front of the proxy pass the WWW-Authenticate header through")
	}
	if !slices.Contains(accepted, m[1]) {
		return name.Result(Fail, fmt.Sprintf("the 401 points at %s, want %s", m[1], accepted[0]), "set the public URL to the URL users enter")
	}
	if res := p.resourceMetadata(name, m[1]); res.Status != Pass {
		return res
	}
	return name.Result(Pass, "401 with resource_metadata "+m[1]+", which resolves", "")
}

// host reports whether the proxy accepted the Host clients send; it runs after the requests above.
func (p *prober) host() Result {
	name := CheckHostHeader
	if !p.answered {
		return name.Result(Skip, "the proxy did not answer, so its Host check was not reached", "")
	}
	if p.misdHost {
		return name.Result(Fail, "the proxy answered 421: it did not accept the Host header it received for "+p.t.Resource.Host, "make the reverse proxy in front of it forward the original Host, or add the Host it sends to "+p.t.HostsSetting)
	}
	return name.Result(Pass, "the proxy accepted Host "+p.t.Resource.Host, "")
}

// assertionKeys follows OIDC discovery as a verifier that has nothing else does (MCP Toolbox's
// generic auth, OpenSearch's openid domain): the discovery document must name byward's issuer and a
// jwks_uri that serves the key signing the identity assertion (ADR-0016 amendment, #207).
func (p *prober) assertionKeys(target string) Result {
	name := CheckAssertionKeys
	r := p.do(http.MethodGet, target, nil, nil)
	switch {
	case r.err != nil && r.status == 0:
		return p.unreachable(name, target, r.err)
	case r.err != nil:
		return name.Result(Fail, target+": "+r.err.Error(), "make whatever is in front of the proxy pass this path through unchanged")
	case r.status != http.StatusOK:
		return p.unexpected(name, target, r, http.StatusOK)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(r.body, &doc); err != nil || doc.Issuer != p.t.Issuer || doc.JWKSURI == "" {
		return name.Result(Fail, target+" does not name the issuer "+p.t.Issuer+" and a jwks_uri, so a verifier that uses discovery cannot find the assertion keys", "make whatever is in front of the proxy pass this path through unchanged; the proxy's own document has both")
	}
	k := p.do(http.MethodGet, doc.JWKSURI, nil, nil)
	switch {
	case k.err != nil && k.status == 0:
		return p.unreachable(name, doc.JWKSURI, k.err)
	case k.err != nil:
		return name.Result(Fail, doc.JWKSURI+": "+k.err.Error(), "make whatever is in front of the proxy pass this path through unchanged")
	case k.status != http.StatusOK:
		return p.unexpected(name, doc.JWKSURI, k, http.StatusOK)
	}
	type jwk struct {
		KeyID string `json:"kid"`
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(k.body, &set); err != nil || !slices.ContainsFunc(set.Keys, func(key jwk) bool { return key.KeyID == p.t.AssertionKeyID }) {
		return name.Result(Fail, doc.JWKSURI+" does not serve the signing key "+p.t.AssertionKeyID+", so verifiers refuse every assertion", "route /.well-known/jwks.json on this host to the proxy, not to the upstream or another service")
	}
	return name.Result(Pass, "discovery names "+doc.JWKSURI+", which serves the signing key "+p.t.AssertionKeyID, "")
}
