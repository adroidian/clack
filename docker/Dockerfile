# Clack relay — public relay image.
#
# Build source is the pinned v1.1.0 release bundle (sha256 in BUILD).
# No application source is fetched from the network at build time; the relay is
# stdlib-only Python (+ the vendored ed25519.py in the bundle).
#
# Networking note: relay.py v1.1.0 has a `bind` config knob. This image's
# first-boot config binds 0.0.0.0 (via CLACK_BIND in docker-compose.yml),
# so it runs on standard bridge networking with a published port —
# reachable at http://127.0.0.1:<port> from the host, exactly what a
# same-box cloudflared needs (see docker-compose.yml and README).

# This digest is the registry-verified linux/amd64 manifest. Compose declares
# the same platform explicitly; native ARM packaging is not claimed.
FROM python:3.12-slim@sha256:44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b

LABEL org.opencontainers.image.title="clack-relay" \
      org.opencontainers.image.version="1.1.0" \
      org.opencontainers.image.revision="693ae2df200ba69b4446484239247082e18fb81a" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/adroidian/clack"

COPY clack-relay-bundle-v1.1.0.tar.gz SHA256SUMS-v1.1.0.txt /tmp/
RUN set -eux; \
    cd /tmp; \
    sha256sum -c SHA256SUMS-v1.1.0.txt; \
    mkdir -p /app; \
    tar xzf clack-relay-bundle-v1.1.0.tar.gz -C /tmp; \
    cp /tmp/clack-relay/relay.py /tmp/clack-relay/ed25519.py /tmp/clack-relay/e2ee.py /tmp/clack-relay/federation_cns.py /tmp/clack-relay/relay-cli.py /app/; \
    cp -r /tmp/clack-relay/clack-client /app/; \
    rm -rf /tmp/clack-relay-bundle-v1.1.0.tar.gz /tmp/SHA256SUMS-v1.1.0.txt /tmp/clack-relay; \
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
