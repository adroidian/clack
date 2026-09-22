clack-relay docker image — build provenance
==============================================
relay version : 0.2.11
source commit : ccb5ccd (local branch v0.2.10-local, linear on published a2c9564)
bundle        : clack-relay-bundle-v0.2.11.tar.gz
bundle sha256 : bf6a1ad3652d370f146d6e667ba5855186772df6606fe500a1d677faaede6a85
base image    : python:3.12-slim
built         : 2026-09-22 (smoke-tested locally; NOT published or deployed)

The bundle is the v0.2.11 release artifact (118/118 tests green). The image
copies relay.py, ed25519.py and relay-cli.py from it verbatim; container
helpers (entrypoint, config generator, healthcheck) are local to docker/
and are not part of the relay source tree.
