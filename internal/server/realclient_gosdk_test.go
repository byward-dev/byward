//go:build integration

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// ADR-0024 §3: the go-sdk client (github.com/modelcontextprotocol/go-sdk v1.8.0, pinned in go.mod)
// discovers byward from its 401, signs in as a pre-registered public client with PKCE through the
// consent page and the fake IdP, and calls the upstream's tool with the access token.
func TestIntegrationGoSDKClientSignsInAndCallsATool(t *testing.T) {
	env := newRealClientEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	signIns := 0
	h, err := mcpauth.NewAuthorizationCodeHandler(&mcpauth.AuthorizationCodeHandlerConfig{
		PreregisteredClient: &oauthex.ClientCredentials{ClientID: realClientID},
		RedirectURL:         "http://127.0.0.1:18765/callback", // never listened on: the scripted browser hands back the redirect
		AuthorizationCodeFetcher: func(_ context.Context, args *mcpauth.AuthorizationArgs) (*mcpauth.AuthorizationResult, error) {
			signIns++
			redirect, err := env.browse(args.URL)
			if err != nil {
				return nil, err
			}
			u, err := url.Parse(redirect)
			if err != nil {
				return nil, err
			}
			q := u.Query()
			if q.Get("code") == "" {
				return nil, fmt.Errorf("redirect without an authorization code: %s", redirect)
			}
			return &mcpauth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "go-sdk-real-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: env.MCPURL, OAuthHandler: h}, nil)
	if err != nil {
		t.Fatalf("connect through byward: %v", err)
	}
	defer func() { _ = session.Close() }()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: echoTool, Arguments: map[string]any{"text": realClientText}})
	if err != nil {
		t.Fatalf("call the upstream's tool: %v", err)
	}
	if res.IsError || len(res.Content) != 1 {
		b, _ := json.Marshal(res)
		t.Fatalf("tool result %s, want one text block", b)
	}
	if text, ok := res.Content[0].(*mcp.TextContent); !ok || text.Text != realClientText {
		t.Fatalf("tool result %+v, want the echoed text", res.Content[0])
	}
	if signIns != 1 {
		t.Fatalf("sign-ins: %d, want exactly 1", signIns)
	}
	env.requireOneToolCallWithOnlyTheAssertion(t)
}
