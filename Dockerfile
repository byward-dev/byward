# Built by goreleaser from prebuilt binaries (`mise run release:snapshot`); `docker build .` does not work.
# The paths and uid below are public interface (ADR-0019): changing them is a breaking change.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
ARG TARGETPLATFORM
COPY --chmod=0555 $TARGETPLATFORM/mcp-authproxy /usr/local/bin/mcp-authproxy
COPY LICENSE NOTICE /usr/share/doc/mcp-authproxy/
COPY build/licenses/ /usr/share/doc/mcp-authproxy/third_party/
USER 65532:65532
WORKDIR /var/lib/mcp-authproxy
ENTRYPOINT ["/usr/local/bin/mcp-authproxy"]
