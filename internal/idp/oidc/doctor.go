package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/idp"
)

// Diagnosis names the settings doctor's fixes refer to.
type Diagnosis struct {
	ClientIDSetting string
	// CredentialSetting is the setting holding the IdP app's secret or private key; KeyCredential
	// reports which (private_key_jwt).
	CredentialSetting string
	KeyCredential     bool
}

// DiagnoseClient is doctor's check that the IdP accepts the proxy's client ID and credential,
// without a user (#288). It redeems a made-up authorization code: an IdP that authenticates the
// client before it looks at the code refuses a wrong client ID, secret or key (invalid_client,
// unauthorized_client, or access_denied with 401), and answers a right one invalid_grant (the code).
// Every preset's order was measured (Preset.ClientCheckedFirst); for plain OIDC a pass notes that
// the order is assumed. The IdP's error_description is never shown: an IdP may echo the request,
// secret included, into it.
func (p *Provider) DiagnoseClient(ctx context.Context, d Diagnosis) doctor.Result {
	check := doctor.CheckClientCredential
	if p.cfg.ClientAuth == nil {
		return check.Result(doctor.Skip, "a public client has no credential to check", "")
	}
	m, err := p.discover(ctx)
	if err != nil {
		return check.Result(doctor.Skip, "not probed: discovery failed", "")
	}
	_, err = p.token(ctx, m, url.Values{"grant_type": {"authorization_code"}, "code": {"byward-doctor-probe-" + unissued()},
		"redirect_uri": {p.cfg.RedirectURL}, "code_verifier": {unissued() + unissued()}})
	var ie *idp.Error
	var netErr net.Error // the http.Client's own error, a body read that timed out, envproxy.Error
	switch {
	case err == nil:
		return check.Result(doctor.Warn, "the IdP issued tokens for a made-up authorization code", "check the IdP's token endpoint: it must refuse unknown codes")
	case errors.Is(err, idp.ErrCredential):
		return check.Result(doctor.Fail, "the proxy cannot make its credential: "+err.Error(), "check "+d.CredentialSetting)
	case errors.As(err, &netErr) || errors.Is(err, io.ErrUnexpectedEOF) || !errors.As(err, &ie): // no whole answer
		return check.Result(doctor.Fail, "the IdP's token endpoint did not answer in full: "+err.Error(),
			"check that the proxy's host reaches "+m.TokenEndpoint+" and gets its whole answer")
	case ie.OAuth == "":
		return check.Result(doctor.Fail, "the IdP's token endpoint gave no OAuth answer: "+err.Error(), "check "+m.TokenEndpoint+": it must be the IdP's token endpoint")
	case refusesClient(ie):
		return check.Result(doctor.Fail, fmt.Sprintf("the IdP refused the client ID or its credential (%s)", answer(ie)), p.credentialFix(d, ie.OAuth == "invalid_client"))
	case ie.OAuth == "invalid_grant" && ie.Status/100 == 4:
		msg := "the IdP accepted the client ID and credential (it refused the made-up code, as it should)"
		if !p.preset.ClientCheckedFirst {
			msg += "; this assumes the IdP checks the client before the code, as the presets were measured to"
		}
		return check.Result(doctor.Pass, msg, "")
	}
	return check.Result(doctor.Warn, fmt.Sprintf("the IdP's answer (%s) does not tell whether it accepted the credential", answer(ie)),
		"sign in once to check the credential")
}

// credentialFix is the fix for a refused credential; badClient is an invalid_client answer, the only
// one that leads with a key algorithm the preset refuses, as at sign-in (#306).
func (p *Provider) credentialFix(d Diagnosis, badClient bool) string {
	if d.KeyCredential {
		fix := fmt.Sprintf("register the public key of %s with the IdP app %s (private_key_jwt), and check %s", d.CredentialSetting, p.cfg.ClientID, d.ClientIDSetting)
		info, ok := p.cfg.ClientAuth.(idp.AssertionInfo)
		switch {
		case !ok: // a credential that does not describe its algorithm: nothing to add
		case badClient && slices.Contains(p.preset.RefusedAssertionAlgs, info.SigningAlgorithm()): // the likely cause first (#306)
			fix = refusedAlgLead(info.SigningAlgorithm(), p.preset, p.cfg.KeyAlgSetting) + "; otherwise " + fix
		default: // name the algorithm after the usual checks (#306)
			fix += "; the key signs with " + info.SigningAlgorithm() + ": the IdP must accept " + info.SigningAlgorithm() + " for client assertions"
		}
		return fix
	}
	return fmt.Sprintf("set %s to the IdP app's current secret, and %s to its client ID", d.CredentialSetting, d.ClientIDSetting)
}

// answer is the IdP's error code, kept to the characters OAuth error codes use and at most 64 of
// them, and the HTTP status.
func answer(ie *idp.Error) string {
	code := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			return r
		}
		return -1
	}, strings.ToLower(ie.OAuth))
	if len(code) > 64 {
		code = code[:64]
	}
	return fmt.Sprintf("%s, HTTP %d", code, ie.Status)
}

// unissued is 16 random bytes in hex: a code and a verifier no IdP has issued.
func unissued() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
