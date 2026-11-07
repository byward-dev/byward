package fakeidp

import (
	"crypto/sha256"
	"slices"
	"strings"
	"time"
)

// GraphAppID is Microsoft Graph's application ID, the `aud` of Graph tokens.
const GraphAppID = "00000003-0000-0000-c000-000000000000"

// groupsOverageLimit is Entra's group count limit for JWTs.
const groupsOverageLimit = 200

var oidcScopes = []string{"openid", "profile", "email", "offline_access"}

// resource is the one non-OIDC resource an Entra request asks scopes for.
type resource struct {
	aud   string   // the resource app's client ID, or Graph's app ID
	perms []string // permission names, e.g. access_as_user or .default
	app   *Client  // nil for resources not registered at the fake (Graph)
}

func (r *resource) graph() bool { return r.aud == GraphAppID }

// v1 reports whether the resource app asks for v1 access tokens.
func (r *resource) v1() bool { return r.app != nil && r.app.AccessTokenVersion == 1 }

// v1Claims turns v2 access-token claims into the v1 form: the sts.windows.net issuer, the
// Application ID URI as `aud`, and `appid` in place of `azp`. Only the api:// form of the resource
// is modelled; the `aud` of a v1 token requested by the GUID form is not.
func (r *resource) v1Claims(m map[string]any, tid string) {
	m["iss"] = "https://sts.windows.net/" + tid + "/"
	m["aud"] = "api://" + r.aud
	m["ver"] = "1.0"
	m["appid"], m["appidacr"] = m["azp"], m["azpacr"]
	delete(m, "azp")
	delete(m, "azpacr")
}

// scopeString is the `scope` value Entra returns: the resource's scopes in full form.
func (r *resource) scopeString() string {
	prefix := "api://" + r.aud + "/"
	if r.graph() {
		prefix = "https://graph.microsoft.com/"
	}
	out := make([]string, len(r.perms))
	for i, p := range r.perms {
		out[i] = prefix + p
	}
	return strings.Join(out, " ")
}

// resolveResource finds the single resource that scopes refer to; nil means only OIDC scopes.
// Entra allows one resource per request. Caller holds p.mu.
func (p *IdP) resolveResource(scopes []string) (*resource, *Failure) {
	if p.profile != Entra {
		return nil, nil
	}
	var res *resource
	for _, s := range scopes {
		if slices.Contains(oidcScopes, s) {
			continue
		}
		prefix, perm := "https://graph.microsoft.com", s
		if i := strings.LastIndex(s, "/"); i >= 0 {
			prefix, perm = s[:i], s[i+1:]
		}
		aud, app := "", (*Client)(nil)
		switch id := strings.TrimPrefix(prefix, "api://"); {
		case prefix == "https://graph.microsoft.com" || id == GraphAppID:
			aud = GraphAppID
		default:
			c, ok := p.cfg.clients[id]
			if !ok || perm == "" {
				f := InvalidScope
				return nil, &f
			}
			if c.NoIdentifierURI && strings.HasPrefix(prefix, "api://") {
				return nil, failure(ResourceNotFound)
			}
			aud, app = c.ID, &c
		}
		if res == nil {
			res = &resource{aud: aud, app: app}
		} else if res.aud != aud {
			f := InvalidScope
			f.Description = "The request contains scopes for more than one resource."
			return nil, &f
		}
		res.perms = append(res.perms, perm)
	}
	return res, nil
}

// pairwiseSub is Entra's `sub`: stable per user and app, different between apps.
func pairwiseSub(tid, oid, appID string) string {
	sum := sha256.Sum256([]byte(tid + "|" + oid + "|" + appID))
	return b64.EncodeToString(sum[:])
}

func (p *IdP) baseClaims(iss, aud string, now time.Time) map[string]any {
	return map[string]any{
		"iss": iss,
		"aud": aud,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(p.cfg.tokenLifetime).Unix(),
	}
}

func (p *IdP) addGroups(m map[string]any, u User) {
	if len(u.Roles) > 0 {
		m["roles"] = u.Roles
	}
	if len(u.Groups) == 0 && !u.GroupsOverage {
		return
	}
	if u.GroupsOverage || len(u.Groups) > groupsOverageLimit {
		m["_claim_names"] = map[string]string{"groups": "src1"}
		m["_claim_sources"] = map[string]any{"src1": map[string]string{
			"endpoint": "https://graph.windows.net/" + u.TenantID + "/users/" + u.OID + "/getMemberObjects",
		}}
		return
	}
	m["groups"] = u.Groups
}

// idToken builds an ID token for user u at client clientID. Caller holds p.mu.
func (p *IdP) idToken(clientID string, u User, scopes []string, nonce string, authTime, now time.Time) string {
	iss := p.issuerFor(u.TenantID)
	m := p.baseClaims(iss, clientID, now)
	if nonce != "" {
		m["nonce"] = nonce
	}
	profile := slices.Contains(scopes, "profile")
	email := slices.Contains(scopes, "email") && u.Email != ""
	if p.profile == Entra {
		p.entraIDClaims(m, clientID, u, profile, email)
	} else {
		p.genericIDClaims(m, clientID, u, authTime, profile, email)
	}
	return p.sign(m)
}

func (p *IdP) entraIDClaims(m map[string]any, clientID string, u User, profile, email bool) {
	m["sub"] = pairwiseSub(u.TenantID, u.OID, clientID)
	m["oid"] = u.OID
	m["tid"] = u.TenantID
	m["ver"] = "2.0"
	m["uti"] = randomToken()[:22]
	if profile {
		m["name"] = u.Name
		m["preferred_username"] = u.PreferredUsername
	}
	if email {
		m["email"] = u.Email
	}
	p.addGroups(m, u)
}

func (p *IdP) genericIDClaims(m map[string]any, clientID string, u User, authTime time.Time, profile, email bool) {
	m["sub"] = u.Subject
	m["azp"] = clientID
	m["auth_time"] = authTime.Unix()
	if profile {
		m["name"] = u.Name
		m["preferred_username"] = u.PreferredUsername
	}
	if email {
		m["email"] = u.Email
		if p.cfg.emailAsString {
			m["email_verified"] = map[bool]string{true: "true", false: "false"}[u.EmailVerified]
		} else {
			m["email_verified"] = u.EmailVerified
		}
	}
	if u.HostedDomain != "" {
		m["hd"] = u.HostedDomain
	}
	if len(u.Groups) > 0 {
		m["groups"] = u.Groups
	}
}

// azpacr is how the client authenticated: 0 public, 1 secret, 2 certificate.
func azpacr(method string) string {
	switch method {
	case "client_secret_basic", "client_secret_post":
		return "1"
	case "private_key_jwt", "federated": // federated: assumed like a certificate, not verified
		return "2"
	}
	return "0"
}

// userAccessToken is a delegated Entra access token for res, requested by clientID. Caller holds
// p.mu.
func (p *IdP) userAccessToken(res *resource, clientID, method string, u User, now time.Time) string {
	if res.graph() {
		return p.graphToken(res, clientID, method, u, now)
	}
	m := p.baseClaims(p.issuerFor(u.TenantID), res.aud, now)
	m["sub"] = pairwiseSub(u.TenantID, u.OID, res.aud)
	m["oid"] = u.OID
	m["tid"] = u.TenantID
	m["ver"] = "2.0"
	m["scp"] = strings.Join(res.perms, " ")
	m["azp"] = clientID
	m["azpacr"] = azpacr(method)
	m["name"] = u.Name
	m["preferred_username"] = u.PreferredUsername
	m["uti"] = randomToken()[:22]
	p.addGroups(m, u)
	if res.v1() {
		res.v1Claims(m, u.TenantID)
	}
	return p.sign(m)
}

// graphToken mimics the v1 Graph token observed in the real-tenant test (ADR-0012).
func (p *IdP) graphToken(res *resource, clientID, method string, u User, now time.Time) string {
	m := p.baseClaims("https://sts.windows.net/"+u.TenantID+"/", GraphAppID, now)
	m["sub"] = pairwiseSub(u.TenantID, u.OID, GraphAppID)
	m["oid"] = u.OID
	m["tid"] = u.TenantID
	m["ver"] = "1.0"
	m["scp"] = strings.Join(res.perms, " ")
	m["appid"] = clientID
	m["appidacr"] = azpacr(method)
	m["idtyp"] = "user"
	m["name"] = u.Name
	m["upn"] = u.PreferredUsername
	return p.sign(m)
}

// appToken is an app-only (client credentials) Entra token for res. Caller holds p.mu.
func (p *IdP) appToken(res *resource, c Client, method string, now time.Time) string {
	iss := p.issuerFor(p.cfg.tenantID)
	if res.graph() {
		iss = "https://sts.windows.net/" + p.cfg.tenantID + "/"
	}
	m := p.baseClaims(iss, res.aud, now)
	m["sub"] = c.ServicePrincipalID
	m["oid"] = c.ServicePrincipalID
	m["tid"] = p.cfg.tenantID
	m["uti"] = randomToken()[:22]
	if res.graph() {
		m["ver"] = "1.0"
		m["appid"] = c.ID
		m["appidacr"] = azpacr(method)
	} else {
		m["ver"] = "2.0"
		m["azp"] = c.ID
		m["azpacr"] = azpacr(method)
	}
	if roles := c.AppRoles[res.aud]; len(roles) > 0 {
		m["roles"] = roles
	}
	if p.cfg.idtyp {
		m["idtyp"] = "app"
	}
	if !res.graph() && res.v1() {
		res.v1Claims(m, p.cfg.tenantID)
	}
	return p.sign(m)
}

// genericAccessToken is the generic profile's access token: a JWT for the client itself.
func (p *IdP) genericAccessToken(clientID string, u User, scopes []string, now time.Time) string {
	m := p.baseClaims(p.issuerFor(""), clientID, now)
	m["sub"] = u.Subject
	m["client_id"] = clientID
	m["scope"] = strings.Join(scopes, " ")
	m["jti"] = randomToken()[:22]
	return p.sign(m)
}
