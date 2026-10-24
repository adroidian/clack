#!/usr/bin/env python3
"""Build the deterministic Clack runtime and focused-verification bundle."""

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

MANDATORY = {
    "relay.py",
    "relay-cli.py",
    "e2ee.py",
    "ed25519.py",
    "federation_adapter.py",
    "federation_authority.py",
    "federation_cns.py",
    "federation_e2ee_v2.py",
    "serve_relay.py",
    "signed_client.py",
    "test-cli-bootstrap.py",
    "test-register-key.py",
    "tests/test_cli_publication_platform.py",
    "tests/test_cli_provisioned_reader.py",
    "QUICKSTART.md",
    "clack-client/clack_client/__init__.py",
    "clack-client/clack_client/requests.py",
    "clack-client/mcp_server/server.py",
    "tests/test_config_peer_restart.py",
    "tests/test_public_requests.py",
    "tests/test_new_agent_invitations.py",
    "tests/test_new_agent_cli.py",
    "tests/test_curl_transport_custody.py",
    "clack-client/clack_client/invitations.py",
    "docs/short-invitations-new-agents.md",
}

ROOT_SOURCE = (
    "relay.py",
    "relay-cli.py",
    "e2ee.py",
    "ed25519.py",
    "federation_adapter.py",
    "federation_authority.py",
    "federation_cns.py",
    "federation_e2ee_v2.py",
    "serve_relay.py",
    "signed_client.py",
)


def run(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    repo = args.repo.resolve()
    commit = run(repo, "rev-parse", f"{args.commit}^{{commit}}").decode().strip()
    paths = [
        "LICENSE",
        "README.md",
        "JOIN.md",
        "CLIENT_CONTRACT.md",
        "CHANGELOG.md",
        *ROOT_SOURCE,
        "clack-client",
        "test-cli-bootstrap.py",
        "test-register-key.py",
        "tests/test_cli_publication_platform.py",
        "tests/test_cli_provisioned_reader.py",
        "QUICKSTART.md",
        "tests/test_config_peer_restart.py",
        "tests/test_public_requests.py",
        "tests/test_new_agent_invitations.py",
        "tests/test_new_agent_cli.py",
        "tests/test_curl_transport_custody.py",
        "docs/short-invitations-new-agents.md",
    ]
    prefix = "clack-relay/"
    # Pin Git's archive mode mask so ambient repository/global configuration
    # cannot alter member modes or the resulting bytes.
    archive = run(
        repo,
        "-c",
        "tar.umask=0002",
        "archive",
        "--format=tar",
        "--prefix=" + prefix,
        commit,
        "--",
        *paths,
    )

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        members = tar.getmembers()
        names_seen: set[str] = set()
        archive_names: set[str] = set()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise SystemExit(f"unsafe archive path: {member.name}")
            if member.name in names_seen:
                raise SystemExit(f"duplicate archive path: {member.name}")
            names_seen.add(member.name)
            if not (member.isdir() or member.isfile()):
                raise SystemExit(f"unsupported archive member: {member.name}")
            if member.isfile():
                archive_names.add(member.name)
    names = {
        name[len(prefix) :]
        for name in archive_names
        if name.startswith(prefix)
    }
    missing = sorted(MANDATORY - names)
    if missing:
        raise SystemExit(f"missing mandatory bundle files: {missing}")
    forbidden = sorted(
        name
        for name in names
        if name.endswith(".tar.gz") or name.startswith(".git")
    )
    if forbidden:
        raise SystemExit(f"forbidden nested/archive files: {forbidden}")

    output = Path(os.path.abspath(args.out))
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9
            ) as compressed:
                compressed.write(archive)
            raw.flush()
            os.fsync(raw.fileno())
        temporary.chmod(0o644)
        with gzip.open(temporary, "rb") as compressed:
            if compressed.read() != archive:
                raise SystemExit("compressed bundle verification failed")
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        size = temporary.stat().st_size
        os.replace(temporary, output)
        directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()

    print(f"commit={commit}")
    print(f"files={len(names)}")
    print(f"bytes={size}")
    print(f"sha256={digest}")


if __name__ == "__main__":
    main()
