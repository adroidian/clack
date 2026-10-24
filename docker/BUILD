clack-relay Docker build provenance
===================================
relay version   : 1.2.0
source commit   : 30c348366602b8577c9ad01eb7e228c9bf179d16
source tree     : 2ee96d33528c167858c1e67834b230be8c698d19
bundle          : clack-relay-bundle-v1.2.0.tar.gz
bundle bytes    : 296850
bundle sha256   : f180b78e588ffdbb7633761d0c1def9a4a1398510aa7e147b4b481cf9deb0d33
bundle payloads : 40 files (47 tar entries including directories)
builder         : build_bundle.py
builder sha256  : 5bcd3b7b41fb1e4c44811cbfba9336dc14f2e31572abe9fade011120a87b0e41
base image      : python:3.12-slim@sha256:44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b
base platform   : linux/amd64
generated       : 2026-10-24

The bundle is generated only from the recorded source commit. It contains the
relay and federation source modules, standalone CLI, reference client/MCP
server, and the focused release-verification tests: relay public requests,
client/CLI/MCP conformance and public requests, standalone CLI bootstrap,
original registration security, publication-platform and provisioned-reader
API-contract qualification, new-agent server/CLI invitation and real default-curl
custody/origin controls, with the required QUICKSTART and private-invitation docs.
It does not claim to carry the repository's inherited broad legacy suite. It
does not contain prior release bundles, credentials, deployment state, or
website source.

Reproduce from the repository root:

  ./docker/build_bundle.py \
    --repo . \
    --commit 30c348366602b8577c9ad01eb7e228c9bf179d16 \
    --out docker/clack-relay-bundle-v1.2.0.tar.gz

The local integration run generated identical bytes with ambient Git tar.umask
settings 0022 and 0077 (and process umasks 0022 and 0077); the builder pins the archive mode mask and
atomically replaces the destination only after gzip verification. Dockerfile
copies the literal v1.2.0 bundle plus checksum manifest and verifies the digest
before extraction; those inputs are not build-argument overridable. Runtime
image IDs and production backup/cutover receipts are deployment evidence and
are intentionally kept outside this public source file.
