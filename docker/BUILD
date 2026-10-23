clack-relay Docker build provenance
===================================
relay version   : 1.1.0
source commit   : 693ae2df200ba69b4446484239247082e18fb81a
source tree     : 61ad2ed73b14dfc6939bd1f4ddad4a2b463381f3
bundle          : clack-relay-bundle-v1.1.0.tar.gz
bundle bytes    : 269861
bundle sha256   : 3ed055a649f6a07fe0f0d93212d012092761cb515e771cc227dfd1f5851b6489
bundle payloads : 35 files (41 tar entries including directories)
builder         : build_bundle.py
builder sha256  : 8d24e837b0dc3ef84f3cc0fe76c235fc04f483c2b87dafbfa59640edc4f7fb8d
base image      : python:3.12-slim@sha256:44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b
base platform   : linux/amd64
generated       : 2026-10-23

The bundle is generated only from the recorded source commit. It contains the
relay and federation source modules, standalone CLI, reference client/MCP
server, and the focused release-verification tests: relay public requests,
client/CLI/MCP conformance and public requests, standalone CLI bootstrap,
original registration security, publication-platform and provisioned-reader
API-contract qualification, with the required QUICKSTART document.
It does not claim to carry the repository's inherited broad legacy suite. It
does not contain prior release bundles, credentials, deployment state, or
website source.

Reproduce from the repository root:

  ./docker/build_bundle.py \
    --repo . \
    --commit 693ae2df200ba69b4446484239247082e18fb81a \
    --out docker/clack-relay-bundle-v1.1.0.tar.gz

The local integration run generated identical bytes with ambient Git tar.umask
settings 0022 and 0077 (and process umasks 0022 and 0077); the builder pins the archive mode mask and
atomically replaces the destination only after gzip verification. Dockerfile
copies the literal v1.1.0 bundle plus checksum manifest and verifies the digest
before extraction; those inputs are not build-argument overridable. Runtime
image IDs and production backup/cutover receipts are deployment evidence and
are intentionally kept outside this public source file.
