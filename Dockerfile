# Built by goreleaser from prebuilt binaries (`mise run release:snapshot`); `docker build .` does not work.
# The paths and uid below are public interface (ADR-0019): changing them is a breaking change.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
ARG TARGETPLATFORM
COPY --chmod=0555 $TARGETPLATFORM/byward /usr/local/bin/byward
COPY LICENSE /usr/share/doc/byward/
COPY build/licenses/ /usr/share/doc/byward/third_party/
USER 65532:65532
WORKDIR /var/lib/byward
ENTRYPOINT ["/usr/local/bin/byward"]
