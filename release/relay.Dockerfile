# The self-hosted relay image (docs/release.md): the static relay and nothing
# else. No shell, no package manager, no libc; runs as an unprivileged user
# with one state volume. Run it with a read-only root and core dumps off, as in
# release/compose.yaml. Built by release/build.sh from the release binaries
# (the build context holds them and an empty state/ folder), offline, with
# rewritten timestamps, so its digest is reproducible and signed.

FROM scratch AS relay-amd64
COPY --chmod=0555 mousse-relay-x86_64-unknown-linux-musl /mousse-relay

FROM scratch AS relay-arm64
COPY --chmod=0555 mousse-relay-aarch64-unknown-linux-musl /mousse-relay

FROM relay-${TARGETARCH}
COPY --chown=65532:65532 --chmod=0700 state /state
LABEL org.opencontainers.image.title="mousse-relay" \
      org.opencontainers.image.source="https://github.com/mousse-agent/mousse-net" \
      org.opencontainers.image.licenses="MIT"
USER 65532:65532
VOLUME ["/state"]
EXPOSE 443
ENTRYPOINT ["/mousse-relay"]
CMD ["run", "--state", "/state"]
