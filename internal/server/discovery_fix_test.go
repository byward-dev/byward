package server

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type failingDiscovery struct{}

func (failingDiscovery) Ready(context.Context) error { return errors.New("connection refused") }

// doctor's fix for a failed discovery asks for https only where https is what the issuer needs: an
// http issuer is allowed on loopback under --dev, and telling that operator "over https" sends them
// the wrong way (L158).
func TestTheDiscoveryFixAsksForHTTPSOnlyOfAnHTTPSIssuer(t *testing.T) {
	for issuer, wantHTTPS := range map[string]bool{
		"https://sso.example.com/realms/acme": true,
		"http://127.0.0.1:8180/realms/byward": false,
	} {
		r := diagnoseDiscovery(context.Background(), failingDiscovery{}, issuer)
		if len(r) != 1 || !strings.HasPrefix(r[0].Fix, "BYWARD_OIDC_ISSUER: set it exactly as the IdP's discovery document states its issuer") ||
			strings.HasSuffix(r[0].Fix, ", over https") != wantHTTPS {
			t.Errorf("issuer %s: fix %q; want \"over https\" %v", issuer, r[0].Fix, wantHTTPS)
		}
	}
}
