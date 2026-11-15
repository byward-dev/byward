package fakeupstream

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A custom Handler reads the request as it was sent, body included, and the request is still
// recorded with that body.
func TestAHandlerReadsTheBodyThatWasRecorded(t *testing.T) {
	up := New()
	t.Cleanup(up.Close)
	var seen string
	up.Handler = func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
		w.WriteHeader(http.StatusNoContent)
	}
	const body = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	res, err := http.Post(up.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	got, ok := up.Last()
	if seen != body || !ok || string(got.Body) != body {
		t.Fatalf("the handler read %q and the record holds %q (ok %v), want both %q", seen, got.Body, ok, body)
	}
}
