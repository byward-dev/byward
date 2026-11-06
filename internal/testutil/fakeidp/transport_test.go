package fakeidp

import (
	"net/http"
	"testing"
)

func TestTransportRoutesAnyHostToTheFake(t *testing.T) {
	f := newFixture(t, Entra)
	resp, err := f.idp.HTTPClient().Get(DefaultAuthority + "/" + f.tenant + "/v2.0/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
