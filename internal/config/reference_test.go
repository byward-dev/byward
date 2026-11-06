package config

import (
	"os"
	"testing"
)

const referencePath = "../../docs/reference/settings.md"

func TestReferenceIsCurrent(t *testing.T) {
	want := reference()
	if os.Getenv("MCP_AUTHPROXY_UPDATE_REFERENCE") == "1" {
		if err := os.WriteFile(referencePath, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(referencePath)
	if err != nil || string(got) != want {
		t.Fatalf("%s is stale; run MCP_AUTHPROXY_UPDATE_REFERENCE=1 go test ./internal/config/", referencePath)
	}
}
