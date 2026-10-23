# OCI image of teamcraft-push-gateway. Build from the repository root:
#
#   podman build --format docker -f containers/teamcraft-push-gateway.Containerfile -t teamcraft-push-gateway .
#
# `--format docker` keeps the HEALTHCHECK instruction (the OCI image format has none); orchestrators
# that run the image should configure the same command themselves: `teamcraft-push-gateway healthcheck`.
#
# Base images are pinned by tag and multi-arch index digest so builds are reproducible. Dependabot
# bumps both in the FROM lines; by hand, take the index digest
# (`docker buildx imagetools inspect <image>`, the top-level Digest), never a single-platform one.

FROM docker.io/library/rust:1.99.1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS build
ENV CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_STRIP=symbols
WORKDIR /src
COPY . .
# rust-toolchain.toml would make rustup download a toolchain and the wasm target; the image's own
# Rust (pinned by the base image digest) is what we want.
RUN rm rust-toolchain.toml
RUN --mount=type=cache,id=teamcraft-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=teamcraft-push-gateway-target,target=/src/target \
    cargo build --release --locked --bin teamcraft-push-gateway \
 && install -D target/release/teamcraft-push-gateway /out/teamcraft-push-gateway

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:83b9b50586253821cf63ffcec87d3d94265a093ad30da232039af962dd8f4edf
LABEL org.opencontainers.image.title="teamcraft-push-gateway" \
      org.opencontainers.image.description="TeamCraft push gateway: forwards sealed wake-ups to APNs and FCM" \
      org.opencontainers.image.source="https://github.com/Zeitgleich/TeamCraft" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
COPY --from=build /out/teamcraft-push-gateway /usr/local/bin/teamcraft-push-gateway
# Non-root. The only state is the SQLite database: mount a volume at /var/lib/teamcraft-push-gateway
# writable for UID 65532 (the root filesystem can stay read-only). Credentials come as mounted files
# or TEAMCRAFT_PUSH_GATEWAY__APNS__* / __FCM__* variables; see
# teamcraft-push-gateway.example.toml. Port 8091 (health, metrics) is for
# the operator's network only: do not publish it.
USER 65532:65532
ENV TEAMCRAFT_PUSH_GATEWAY__SERVER__BIND=[::]:8090 \
    TEAMCRAFT_PUSH_GATEWAY__SERVER__HEALTH_BIND=[::]:8091 \
    TEAMCRAFT_PUSH_GATEWAY__DATABASE__PATH=/var/lib/teamcraft-push-gateway/gateway.db \
    TEAMCRAFT_PUSH_GATEWAY__TOKENS__DIR=/var/lib/teamcraft-push-gateway/token-keys
VOLUME /var/lib/teamcraft-push-gateway
EXPOSE 8090/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/teamcraft-push-gateway", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/teamcraft-push-gateway"]
