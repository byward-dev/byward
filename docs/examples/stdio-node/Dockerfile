# Wrap a Node.js stdio MCP server with byward (ADR-0019 image contract).
# Pin both images by digest in production.
ARG BYWARD_IMAGE=ghcr.io/byward-dev/byward:latest
FROM ${BYWARD_IMAGE} AS byward

FROM node:26-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072
COPY --from=byward /usr/local/bin/byward /usr/local/bin/byward
COPY --from=byward --chown=node:node /var/lib/byward /var/lib/byward
USER node
ENTRYPOINT ["/usr/local/bin/byward", "--", "npx", "-y", "@modelcontextprotocol/server-everything"]
