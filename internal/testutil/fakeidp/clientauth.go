package fakeidp

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"slices"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// authenticateClient checks client_secret_basic, client_secret_post, private_key_jwt or a
// public client. Caller holds p.mu.
func (p *IdP) authenticateClient(r *http.Request, tenant string) (Client, string, *Failure) {
	form := r.PostForm
	id := form.Get("client_id")
	basicID, basicSecret, hasBasic := r.BasicAuth()
	if hasBasic {
		// RFC 6749 §2.3.1: the credentials are form-urlencoded inside Basic.
		var err1, err2 error
		basicID, err1 = url.QueryUnescape(basicID)
		basicSecret, err2 = url.QueryUnescape(basicSecret)
		if err1 != nil || err2 != nil || (id != "" && id != basicID) {
			return Client{}, "", failure(InvalidRequest)
		}
		id = basicID
	}
	assertion := form.Get("client_assertion")
	methods := 0
	for _, used := range []bool{hasBasic, form.Has("client_secret"), assertion != ""} {
		if used {
			methods++
		}
	}
	if methods > 1 {
		f := InvalidRequest
		f.Description = "More than one client authentication method was used."
		return Client{}, "", &f
	}
	if id == "" && assertion != "" {
		if j, err := parseJWS(assertion); err == nil {
			id, _ = j.claims["sub"].(string)
		}
	}
	if id == "" {
		f := InvalidRequest
		f.Code, f.Description = 900144, "The request body must contain the following parameter: 'client_id'."
		return Client{}, "", &f
	}
	c, ok := p.cfg.clients[id]
	if !ok {
		return Client{}, "", failure(UnknownClient)
	}
	switch {
	case assertion != "":
		if form.Get("client_assertion_type") != clientAssertionType {
			return Client{}, "", failure(InvalidRequest)
		}
		if len(c.Federated) > 0 {
			if j, err := parseJWS(assertion); err == nil && j.claims["iss"] != c.ID {
				if f := p.checkFederatedAssertion(c, j); f != nil {
					return Client{}, "", f
				}
				return c, "federated", nil
			}
		}
		if f := p.checkClientAssertion(c, assertion, tenant); f != nil {
			return Client{}, "", f
		}
		return c, "private_key_jwt", nil
	case hasBasic:
		if !secretMatches(c, basicSecret) {
			return Client{}, "", failure(InvalidClientSecret)
		}
		return c, "client_secret_basic", nil
	case form.Has("client_secret"):
		if !secretMatches(c, form.Get("client_secret")) {
			return Client{}, "", failure(InvalidClientSecret)
		}
		return c, "client_secret_post", nil
	case c.confidential():
		return Client{}, "", failure(MissingClientCredential)
	}
	return c, "none", nil
}

func secretMatches(c Client, secret string) bool {
	for _, s := range c.Secrets {
		if subtle.ConstantTimeCompare([]byte(s), []byte(secret)) == 1 {
			return true
		}
	}
	return false
}

// checkClientAssertion validates a private_key_jwt assertion the way the real-tenant test saw
// Entra do it (ADR-0012): RS256 or PS256 by default (WithClientAssertionAlgs sets them, and a
// refused alg gets Okta's description), a certificate found by x5t#S256 or x5t, `aud` = the v2 token
// endpoint, `iss` = `sub` = the client ID.
func (p *IdP) checkClientAssertion(c Client, assertion, tenant string) *Failure {
	bad := func(desc string) *Failure {
		f := InvalidClientAssertion
		if desc != "" {
			f.Description = desc
		}
		return &f
	}
	j, err := parseJWS(assertion)
	if err != nil {
		return bad("Client assertion is not a valid JWT.")
	}
	var cert *Certificate
	switch s256, s1, kid := j.str("x5t#S256"), j.str("x5t"), j.str("kid"); {
	case s256 != "":
		cert = findCert(c, func(k *Certificate) string { return k.ThumbprintSHA256() }, s256)
	case s1 != "":
		cert = findCert(c, func(k *Certificate) string { return k.ThumbprintSHA1() }, s1)
	case p.profile == Generic && kid != "":
		cert = findCert(c, func(k *Certificate) string { return k.ThumbprintSHA256() }, kid)
	default:
		return failure(MissingThumbprint)
	}
	if cert == nil {
		return bad("Client assertion contains an invalid signature. The key was not found.")
	}
	algs := p.cfg.assertionAlgs
	if algs == nil {
		algs = []string{"RS256", "PS256"}
	}
	if !slices.Contains(algs, j.str("alg")) {
		return bad("The client_assertion JWT signature algorithm is invalid.") // as Okta words it
	}
	if err := j.verify(&cert.Key.PublicKey, algs...); err != nil {
		return bad("")
	}
	now := p.cfg.clock()
	iss, _ := j.claims["iss"].(string)
	sub, _ := j.claims["sub"].(string)
	if iss != c.ID || sub != c.ID {
		return bad("Client assertion iss and sub must be the client ID.")
	}
	if !audContains(j.claims["aud"], p.assertionAudiences(tenant)...) {
		return bad("Client assertion audience is not the token endpoint.")
	}
	exp, ok := numericDate(j.claims["exp"])
	if !ok || !now.Before(exp) {
		return bad("Client assertion has expired.")
	}
	if nbf, ok := numericDate(j.claims["nbf"]); ok && now.Before(nbf) {
		return bad("Client assertion is not yet valid.")
	}
	return nil
}

// assertionAudiences are the token-endpoint URLs a client assertion may name: the fake's own and,
// for Entra, the one under the real authority. Caller holds p.mu.
func (p *IdP) assertionAudiences(tenant string) []string {
	if p.profile == Generic {
		return []string{p.TokenURL(""), p.issuerFor("")}
	}
	return []string{p.TokenURL(tenant), p.cfg.authority + "/" + tenant + "/oauth2/v2.0/token"}
}

func findCert(c Client, thumb func(*Certificate) string, want string) *Certificate {
	for _, k := range c.Certificates {
		if subtle.ConstantTimeCompare([]byte(thumb(k)), []byte(want)) == 1 {
			return k
		}
	}
	return nil
}

// checkFederatedAssertion accepts another issuer's token as the client's assertion when one of its
// federated identity credentials names that issuer, subject and audience exactly, case-sensitively
// (Microsoft Learn: "Pattern matching isn't supported"), and the token is signed and current.
func (p *IdP) checkFederatedAssertion(c Client, j *jws) *Failure {
	iss, _ := j.claims["iss"].(string)
	sub, _ := j.claims["sub"].(string)
	for _, fc := range c.Federated {
		if fc.Issuer != iss || fc.Subject != sub || !audContains(j.claims["aud"], fc.Audience) {
			continue
		}
		if err := j.verify(&fc.Signer.Key.PublicKey, "RS256"); err != nil {
			return failure(InvalidClientAssertion)
		}
		now := p.cfg.clock()
		if exp, ok := numericDate(j.claims["exp"]); !ok || !now.Before(exp) {
			f := InvalidClientAssertion
			f.Description = "Client assertion has expired."
			return &f
		}
		if nbf, ok := numericDate(j.claims["nbf"]); ok && now.Before(nbf) {
			f := InvalidClientAssertion
			f.Description = "Client assertion is not yet valid."
			return &f
		}
		return nil
	}
	return failure(NoMatchingFederatedCredential)
}
