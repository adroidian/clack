clack-relay docker image — build provenance
==============================================
relay version : 1.0.0
source commit : 77e22e33 (public-safe release, history-corrected)
bundle        : clack-relay-bundle-v1.0.0.tar.gz
bundle sha256 : 7b445b8571a7f376580df31f412a380cc597cc38d79147bf7efe6d0aef168c69
base image    : python:3.12-slim
built         : 2026-10-12 (clean public-safe tree; verified no secrets/private data)

The bundle is the v1.0.0 release artifact from the public-safe tree.
The image copies relay.py, ed25519.py and relay-cli.py from it verbatim;
container helpers (entrypoint, config generator, healthcheck) are local to
docker/ and are not part of the relay source tree.
