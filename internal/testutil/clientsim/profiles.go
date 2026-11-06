package clientsim

// The profiles. Refresh one when its client changes, and say which version or date it was checked
// at; the manual release run updates them (ADR-0024 §2).
var (
	// ClaudeCode as a static client: the operator registers it and passes --client-id.
	ClaudeCode = Profile{
		Client: "Claude Code", Version: "2.1.251 (docs read 2026-11-06)", Cell: "Claude Code × static",
		Registration: Static, ClientID: "claude-code", RedirectURI: "http://localhost:45813/callback",
		ProtocolVersion: "2025-11-25",
		Discovery:       []string{"/.well-known/oauth-protected-resource"}, ASMetadata: []string{"oauth-authorization-server", "openid-configuration"},
		UsesChallenge: false, SendsResource: false, ChecksIss: true,
		Treats403AsAuthFailure: true,
		Facts: []Fact{
			{"checks /.well-known/oauth-protected-resource first; the path-inserted form is not documented", "https://code.claude.com/docs/en/mcp"},
			{"static client: --client-id, --client-secret, --callback-port; redirect http://localhost:<port>/callback", "https://code.claude.com/docs/en/mcp"},
			{"does not send the RFC 8707 resource parameter", "anthropics/claude-code#90497 (closed not planned, 2026-10-31)"},
			{"requests the scope the challenge or the PRM names, none when neither does (oauth.scopes overrides)", "anthropics/claude-code#103778 (open); https://code.claude.com/docs/en/mcp"},
			{"fails a sign-in whose authorization response names an unexpected issuer", "https://code.claude.com/docs/en/mcp"},
			{"marks the server as needing authentication on 401 or 403", "https://code.claude.com/docs/en/mcp"},
			{"re-runs headersHelper on 401/403 (10 s timeout, no caching)", "https://code.claude.com/docs/en/mcp"},
			{"a refused tools/call: one call, no retry, no discovery; the model sees the body text", "runtime test, Claude Code 2.1.142, 2026-11-06"},
			{"authorization server metadata path order", Assumed},
			{"sends MCP revision 2025-11-25 in initialize", Assumed},
			{"refuses an authorization server whose code_challenge_methods_supported lacks S256 (MCP authorization MUST)", Assumed},
		},
	}

	// ClaudeAI is Claude.ai and Claude Desktop remote connectors with CIMD.
	ClaudeAI = Profile{
		Client: "Claude.ai", Version: "docs read 2026-11-06", Cell: "Claude.ai/Desktop × CIMD",
		Registration: CIMD, Document: "claude-ai", RedirectURI: "https://claude.ai/api/mcp/auth_callback", ProtocolVersion: "2025-11-25",
		Discovery:     []string{"/.well-known/oauth-protected-resource/", "/.well-known/oauth-protected-resource"},
		ASMetadata:    []string{"oauth-authorization-server", "openid-configuration"},
		UsesChallenge: true, CIMDNeedsNone: true, SendsResource: true, AddsOfflineAccess: true,
		Facts: []Fact{
			{"follows the 401's resource_metadata; only without one does it try the path-inserted PRM, then the root one (a fallback)", "https://claude.com/docs/connectors/building/authentication"},
			{"uses the first authorization_servers entry and does not fall back (every profile uses the first; none falls back)", "https://claude.com/docs/connectors/building/authentication"},
			{"needs a 401 to read WWW-Authenticate", "https://claude.com/docs/connectors/building/authentication"},
			{"normally picks CIMD only with client_id_metadata_document_supported and none; otherwise DCR", "https://claude.com/docs/connectors/building/authentication"},
			{"redirect https://claude.ai/api/mcp/auth_callback; PKCE S256 always", "https://claude.com/docs/connectors/building/authentication"},
			{"the CIMD document URL is claude.ai's MCP client metadata", Assumed},
			{"sends resource", Assumed},
			{"requests the challenge's scope, else the PRM's scopes_supported, and appends offline_access when the authorization server lists it", "https://claude.com/docs/connectors/building/authentication"},
			{"403 and insufficient_scope handling", Assumed},
			{"checks the redirect's iss (RFC 9207)", Assumed},
			{"authorization server metadata path order", Assumed},
			{"sends MCP revision 2025-11-25 in initialize", Assumed},
			{"refuses an authorization server whose code_challenge_methods_supported lacks S256 (MCP authorization MUST)", Assumed},
		},
	}

	// VSCode with CIMD (its product configuration sets the document URL).
	VSCode = Profile{
		Client: "VS Code", Version: "1.145.2 (source)", Cell: "VS Code × CIMD",
		Registration: CIMD, Document: "vscode", RedirectURI: "http://127.0.0.1:33418/", ProtocolVersion: "2025-11-25",
		Discovery: []string{"/.well-known/oauth-protected-resource/"}, ASMetadata: []string{"oauth-authorization-server", "openid-configuration"},
		UsesChallenge: true, SendsResource: true,
		Treats403AsAuthFailure: true,
		Facts: []Fact{
			{"stored registration, then CIMD when configured (it does not check for none), then DCR", "microsoft/vscode 1.145.2 mainThreadAuthentication.ts:183-194"},
			{"sends resource on authorize and token", "microsoft/vscode 1.145.2 extHostAuthentication.ts:739,749,837,900"},
			{"scope from the challenge, else the PRM's scopes_supported", "microsoft/vscode 1.145.2 extHostMcp.ts:1158-1187"},
			{"treats 401 and 403 as auth errors: new token, then a forced new registration, up to 3 sends", "microsoft/vscode 1.145.2 extHostMcp.ts:871,883-888,1038-1039"},
			{"redirect http://127.0.0.1:33418/ (desktop)", "https://vscode.dev/oauth/client-metadata.json"},
			{"PRM and authorization server metadata path order", Assumed},
			{"checks the redirect's iss (RFC 9207)", Assumed},
			{"sends MCP revision 2025-11-25 in initialize", Assumed},
			{"refuses an authorization server whose code_challenge_methods_supported lacks S256 (MCP authorization MUST)", Assumed},
		},
	}
)

// ChatGPT with CIMD: the stable client ID, which it uses when the authorization server meets
// OpenAI's issuer identification requirements (the broker does: RFC 9207 iss on every response).
var ChatGPT = Profile{
	Client: "ChatGPT", Version: "docs read 2026-11-06", Cell: "ChatGPT × CIMD",
	Registration: CIMD, Document: "chatgpt", RedirectURI: "https://chatgpt.com/connector_platform_oauth_redirect", ProtocolVersion: "2025-11-25",
	Discovery: []string{"/.well-known/oauth-protected-resource"}, ASMetadata: []string{"oauth-authorization-server", "openid-configuration"},
	UsesChallenge: true, PrivateKeyJWT: true, ChecksIss: true, NeedsIssSupported: true, SendsResource: true,
	Facts: []Fact{
		{"prefers CIMD; the stable client ID https://chatgpt.com/oauth/client.json needs iss support and an issuer equal to the PRM's authorization_servers entry", "https://developers.openai.com/plugins/build/auth"},
		{"its document's legacy token_endpoint_auth_method prefers private_key_jwt (RS256, jwks_uri https://chatgpt.com/oauth/jwks.json); ChatGPT picks from the intersection with the server's methods", "https://developers.openai.com/plugins/build/auth; https://chatgpt.com/oauth/client.json"},
		{"redirect https://chatgpt.com/connector_platform_oauth_redirect with the stable client ID", "https://developers.openai.com/plugins/build/auth"},
		{"appends resource to the authorization and token requests; PKCE S256", "https://developers.openai.com/plugins/build/auth"},
		{"finds the PRM at /.well-known/oauth-protected-resource or through the 401's WWW-Authenticate", "https://developers.openai.com/plugins/build/auth"},
		{"rejects an authorization response without the advertised iss", "https://developers.openai.com/plugins/build/auth"},
		{"order of the two authorization server metadata paths", Assumed},
		{"requests offline_access", Assumed},
		{"requests the challenge's scope, else the PRM's scopes_supported", Assumed},
		{"sends MCP revision 2025-11-25 in initialize", Assumed},
		{"403 and insufficient_scope handling", Assumed},
		{"refuses an authorization server whose code_challenge_methods_supported lacks S256 (MCP authorization MUST)", Assumed},
		{"the simulator signs the assertion with a test key served at the document's jwks_uri; the document itself is the captured one", "test setup"},
	},
}

// Cursor with dynamic client registration. Only its registration request is sourced; the rest follows
// the MCP specification until someone checks a Cursor build.
var Cursor = Profile{
	Client: "Cursor", Version: "3.14.27 (forum reports read 2026-11-06)", Cell: "Cursor × DCR",
	Registration: DCR, Document: "cursor", RedirectURI: "https://www.cursor.com/agents/mcp/oauth/callback", ProtocolVersion: "2025-11-25",
	Discovery:     []string{"/.well-known/oauth-protected-resource/", "/.well-known/oauth-protected-resource"},
	ASMetadata:    []string{"oauth-authorization-server", "openid-configuration"},
	UsesChallenge: true, SendsResource: true,
	Facts: []Fact{
		{"registers with DCR; redirect URIs cursor://anysphere.cursor-mcp/oauth/callback, https://www.cursor.com/agents/mcp/oauth/callback and http://localhost:8787/callback", "forum.cursor.com/t/171867 (Cursor staff); forum.cursor.com/t/167608 (user report, Cursor 3.14.27)"},
		{"the other registration fields (grant types, response types, token_endpoint_auth_method none)", Assumed},
		{"signs in with the https or loopback callback, not cursor:// (ADR-0009: the proxy refuses cursor://; open until the HITL compatibility run)", Assumed},
		{"follows the 401's resource_metadata, else the path-inserted PRM, then the root one", Assumed},
		{"authorization server metadata path order", Assumed},
		{"sends resource on authorize and token", Assumed},
		{"requests the challenge's scope, else the PRM's scopes_supported", Assumed},
		{"checks the redirect's iss (RFC 9207)", Assumed},
		{"403 and insufficient_scope handling", Assumed},
		{"sends MCP revision 2025-11-25 in initialize", Assumed},
		{"refuses an authorization server whose code_challenge_methods_supported lacks S256 (MCP authorization MUST)", Assumed},
	},
}

// All lists every profile, for the simulator test.
var All = []Profile{ClaudeCode, ClaudeAI, VSCode, ChatGPT, Cursor}
