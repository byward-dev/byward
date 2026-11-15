package broker

import (
	"reflect"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/idp"
)

// goldenSecrets is a version 1 grant blob with every asserted claim, as the store holds it (before
// sealing) since the claims were kept with the IdP tokens. Grants live 30 days across upgrades, so
// it must keep reading the same, and a new blob must be written the same way.
const goldenSecrets = `{"v":1,"t":{"IDToken":"id","AccessToken":"at","RefreshToken":"rt","Expiry":"2026-11-06T13:00:00Z"},` +
	`"c":{"rol":["byward.user"],"grp":["g1"],"eml":"alex@contoso.example","emv":true,"nam":"Alex Doe"}}`

func goldenGrantSecrets() grantSecrets {
	return grantSecrets{Version: grantSecretsVersion,
		Tokens: idp.Tokens{IDToken: "id", AccessToken: "at", RefreshToken: "rt", Expiry: time.Date(2026, 11, 6, 13, 0, 0, 0, time.UTC)},
		Claims: assertedClaims{Roles: []string{"byward.user"}, Groups: []string{"g1"}, Email: "alex@contoso.example", EmailVerified: true, Name: "Alex Doe"}}
}

func TestAGrantBlobWithClaimsReadsTheSameAndIsWrittenTheSame(t *testing.T) {
	got, err := unmarshalSecrets([]byte(goldenSecrets))
	if err != nil {
		t.Fatal(err)
	}
	want := goldenGrantSecrets()
	if !got.Tokens.Expiry.Equal(want.Tokens.Expiry) {
		t.Fatalf("expiry %v, want %v", got.Tokens.Expiry, want.Tokens.Expiry)
	}
	got.Tokens.Expiry = want.Tokens.Expiry
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read %+v\nwant %+v", got, want)
	}
	if b := marshalSecrets(want.Tokens, want.Claims); string(b) != goldenSecrets {
		t.Fatalf("written\n%s\nwant\n%s", b, goldenSecrets)
	}
}
