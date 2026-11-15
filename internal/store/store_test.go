package store

import (
	"errors"
	"testing"
	"time"
)

// The ErrInvalid rules every adapter applies are the store's own: each field the contract names (or
// argument, for CheckSpend) makes the value invalid on its own, and a value with all of them right
// is valid.
func TestTheInputRulesRefuseEachInvalidFieldAndAcceptAValidValue(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	grant := func(f func(*Grant)) error {
		g := Grant{ID: "g", ClientID: "c", Subject: "s", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
		f(&g)
		return g.CheckNew()
	}
	client := func(f func(*Client)) error {
		c := Client{ID: "c", Metadata: []byte("{}"), CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
		f(&c)
		return c.CheckNew()
	}
	consent := func(f func(*Consent)) error {
		c := Consent{Key: ConsentKey{Issuer: "i", Subject: "s", ClientID: "c", Redirect: "r", Resource: "u"},
			Scopes: []string{"mcp"}, ApprovedAt: t0, ExpiresAt: t0.Add(time.Hour)}
		f(&c)
		return c.CheckNew()
	}
	for _, c := range []struct {
		name  string
		err   error
		valid bool
	}{
		{"a valid grant", grant(func(*Grant) {}), true},
		{"a grant without an ID", grant(func(g *Grant) { g.ID = "" }), false},
		{"a grant without a client ID", grant(func(g *Grant) { g.ClientID = "" }), false},
		{"a grant without a subject", grant(func(g *Grant) { g.Subject = "" }), false},
		{"a grant expiring when it is created", grant(func(g *Grant) { g.ExpiresAt = g.CreatedAt }), false},
		{"a grant expiring before it is created", grant(func(g *Grant) { g.ExpiresAt = g.CreatedAt.Add(-time.Second) }), false},
		{"a valid client", client(func(*Client) {}), true},
		{"a client without an ID", client(func(c *Client) { c.ID = "" }), false},
		{"a client without metadata", client(func(c *Client) { c.Metadata = nil }), false},
		{"a client with empty metadata", client(func(c *Client) { c.Metadata = []byte{} }), false},
		{"a client already used", client(func(c *Client) { c.UsedAt = t0 }), false},
		{"a client expiring when it is created", client(func(c *Client) { c.ExpiresAt = c.CreatedAt }), false},
		{"a client expiring before it is created", client(func(c *Client) { c.ExpiresAt = c.CreatedAt.Add(-time.Second) }), false},
		{"a valid consent", consent(func(*Consent) {}), true},
		{"a consent without an issuer", consent(func(c *Consent) { c.Key.Issuer = "" }), false},
		{"a consent without a subject", consent(func(c *Consent) { c.Key.Subject = "" }), false},
		{"a consent without a client ID", consent(func(c *Consent) { c.Key.ClientID = "" }), false},
		{"a consent without a redirect", consent(func(c *Consent) { c.Key.Redirect = "" }), false},
		{"a consent without a resource", consent(func(c *Consent) { c.Key.Resource = "" }), false},
		{"a consent without scopes", consent(func(c *Consent) { c.Scopes = nil }), false},
		{"a consent with empty scopes", consent(func(c *Consent) { c.Scopes = []string{} }), false},
		{"a consent expiring when it is approved", consent(func(c *Consent) { c.ExpiresAt = c.ApprovedAt }), false},
		{"a consent expiring before it is approved", consent(func(c *Consent) { c.ExpiresAt = c.ApprovedAt.Add(-time.Second) }), false},
		{"spent until later", CheckSpend(t0, t0.Add(time.Second)), true},
		{"spent until now", CheckSpend(t0, t0), false},
		{"spent until before now", CheckSpend(t0, t0.Add(-time.Second)), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			switch {
			case c.valid && c.err != nil:
				t.Errorf("err = %v, want nil", c.err)
			case !c.valid && !errors.Is(c.err, ErrInvalid):
				t.Errorf("err = %v, want ErrInvalid", c.err)
			}
		})
	}
}
