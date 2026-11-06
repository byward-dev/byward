# Wrap a Node.js stdio MCP server with mcp-authproxy (ADR-0019 image contract).
# Pin both images by digest in production.
ARG MCP_AUTHPROXY_IMAGE=ghcr.io/corker/mcp-authproxy:latest
FROM ${MCP_AUTHPROXY_IMAGE} AS mcp-authproxy

FROM node:26-slim
COPY --from=mcp-authproxy /usr/local/bin/mcp-authproxy /usr/local/bin/mcp-authproxy
COPY --from=mcp-authproxy --chown=node:node /var/lib/mcp-authproxy /var/lib/mcp-authproxy
USER node
ENTRYPOINT ["/usr/local/bin/mcp-authproxy", "--", "npx", "-y", "@modelcontextprotocol/server-everything"]
