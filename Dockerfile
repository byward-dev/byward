# Built by goreleaser from prebuilt binaries (`mise run release:snapshot`); `docker build .` does not work.
# The paths and uid below are public interface (ADR-0019): changing them is a breaking change.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
ARG TARGETPLATFORM
COPY --chmod=0555 $TARGETPLATFORM/byward /usr/local/bin/byward
COPY LICENSE /usr/share/doc/byward/
COPY build/licenses/ /usr/share/doc/byward/third_party/
USER 65532:65532
WORKDIR /var/lib/byward
ENTRYPOINT ["/usr/local/bin/byward"]
