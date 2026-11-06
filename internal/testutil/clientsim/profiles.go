package clientsim

// The profiles. Refresh one when its client changes, and say which version or date it was checked
// at; the manual release run updates them (ADR-0024 §2).
var (
	// ClaudeCode as a static client: the operator registers it and passes --client-id.
	ClaudeCode = Profile{
		Client: "Claude Code", Version: "2.1.251 (docs read 2026-11-06)", Cell: "Claude Code × static",
		Registration: Static, ClientID: "claude-code", RedirectURI: "http://localhost:45813/callback",
		Discovery:     []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"},
		UsesChallenge: false, SendsResource: false, Scope: "",
		Treats403AsAuthFailure: true, HeadersHelperOn401: true,
		Facts: []Fact{
			{"checks /.well-known/oauth-protected-resource first; the path-inserted form is not documented", "https://code.claude.com/docs/en/mcp"},
			{"static client: --client-id, --client-secret, --callback-port; redirect http://localhost:<port>/callback", "https://code.claude.com/docs/en/mcp"},
			{"does not send the RFC 8707 resource parameter", "anthropics/claude-code#90497 (closed not planned, 2026-10-31)"},
			{"sends no scope when neither PRM nor the challenge names one", "anthropics/claude-code#103778 (open)"},
			{"marks the server as needing authentication on 401 or 403", "https://code.claude.com/docs/en/mcp"},
			{"re-runs headersHelper on 401/403 (10 s timeout, no caching)", "https://code.claude.com/docs/en/mcp"},
			{"a refused tools/call: one call, no retry, no discovery; the model sees the body text", "runtime test, Claude Code 2.1.142, 2026-11-06"},
			{"authorization server metadata path order", Assumed},
		},
	}

	// ClaudeAI is Claude.ai and Claude Desktop remote connectors with CIMD.
	ClaudeAI = Profile{
		Client: "Claude.ai", Version: "docs read 2026-11-06", Cell: "Claude.ai/Desktop × CIMD",
		Registration: CIMD, ClientID: "claude-ai", RedirectURI: "https://claude.ai/api/mcp/auth_callback",
		Discovery:     []string{"/.well-known/oauth-protected-resource/", "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"},
		UsesChallenge: true, FirstAuthorizationServerOnly: true, CIMDNeedsNone: true,
		SendsResource: true, Scope: "mcp",
		Facts: []Fact{
			{"tries the path-inserted PRM first, then the root one", "https://claude.com/docs/connectors/building/authentication"},
			{"uses the first authorization_servers entry and does not fall back", "https://claude.com/docs/connectors/building/authentication"},
			{"needs a 401 to read WWW-Authenticate", "https://claude.com/docs/connectors/building/authentication"},
			{"picks CIMD only with client_id_metadata_document_supported and none; otherwise DCR", "https://claude.com/docs/connectors/building/authentication"},
			{"redirect https://claude.ai/api/mcp/auth_callback; PKCE S256 always", "https://claude.com/docs/connectors/building/authentication"},
			{"the CIMD document URL is claude.ai's MCP client metadata", Assumed},
			{"sends resource", Assumed},
			{"requests the scope the PRM advertises", Assumed},
			{"403 and insufficient_scope handling", Assumed},
		},
	}

	// VSCode with CIMD (its product configuration sets the document URL).
	VSCode = Profile{
		Client: "VS Code", Version: "1.145.2 (source)", Cell: "VS Code × CIMD",
		Registration: CIMD, ClientID: "vscode", RedirectURI: "http://127.0.0.1:33418/",
		Discovery:     []string{"/.well-known/oauth-protected-resource/", "/.well-known/oauth-authorization-server"},
		UsesChallenge: true, SendsResource: true, Scope: "mcp",
		Treats403AsAuthFailure: true,
		Facts: []Fact{
			{"stored registration, then CIMD when configured (it does not check for none), then DCR", "microsoft/vscode 1.145.2 mainThreadAuthentication.ts:183-194"},
			{"sends resource on authorize and token", "microsoft/vscode 1.145.2 extHostAuthentication.ts:739,749,837,900"},
			{"scope from the challenge, else the PRM's scopes_supported", "microsoft/vscode 1.145.2 extHostMcp.ts:1158-1187"},
			{"treats 401 and 403 as auth errors: new token, then a forced new registration, up to 3 sends", "microsoft/vscode 1.145.2 extHostMcp.ts:871,883-888,1038-1039"},
			{"redirect http://127.0.0.1:33418/ (desktop)", "https://vscode.dev/oauth/client-metadata.json"},
			{"PRM and authorization server metadata path order", Assumed},
		},
	}
)

// All lists every profile, for the simulator test.
var All = []Profile{ClaudeCode, ClaudeAI, VSCode}
