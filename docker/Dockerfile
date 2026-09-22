# Clack relay — public relay image.
#
# Build source is the pinned v0.2.11 release bundle (sha256 in BUILD).
# Nothing is fetched from the network at build time; the relay itself is
# stdlib-only Python (+ the vendored ed25519.py in the bundle).
#
# Networking note: relay.py v0.2.11 has a `bind` config knob. This image's
# first-boot config binds 0.0.0.0 (via CLACK_BIND in docker-compose.yml),
# so it runs on standard bridge networking with a published port —
# reachable at http://127.0.0.1:<port> from the host, exactly what a
# same-box cloudflared needs (see docker-compose.yml and README).

FROM python:3.12-slim

LABEL org.opencontainers.image.title="clack-relay" \
      org.opencontainers.image.version="0.2.11" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/adroidian/clack"

ARG BUNDLE=clack-relay-bundle-v0.2.11.tar.gz
COPY ${BUNDLE} /tmp/bundle.tgz
RUN set -eux; \
    mkdir -p /app; \
    tar xzf /tmp/bundle.tgz -C /tmp; \
    cp /tmp/clack-relay/relay.py /tmp/clack-relay/ed25519.py /tmp/clack-relay/relay-cli.py /app/; \
    rm -rf /tmp/bundle.tgz /tmp/clack-relay; \
    useradd --system --no-create-home --shell /usr/sbin/nologin clack; \
    mkdir -p /data && chown clack:clack /data

# Container-local helpers (not part of the relay source tree).
COPY docker-entrypoint.sh init-config.py healthcheck.py /app/
RUN chmod +x /app/docker-entrypoint.sh /app/healthcheck.py && \
    chmod -R a+rX /app

ENV CLACK_RELAY_BASE=/data \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EXPOSE 18802

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD ["/app/healthcheck.py"]

ENTRYPOINT ["/app/docker-entrypoint.sh"]
