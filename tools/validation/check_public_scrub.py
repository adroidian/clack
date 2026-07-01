#!/usr/bin/env python3
"""Scan a Clack tree for public-mirror scrub findings.

This gate catches high-signal private topology and identity breadcrumbs before a
candidate branch is pushed to a public mirror. It intentionally allows generic
open-source security vocabulary such as "token", "secret", and "/wake" when it
uses example domains or localhost.
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "bin", "dist", "build", "node_modules", ".venv", "vendor"}
TEXT_SUFFIXES = {
    ".go", ".md", ".py", ".json", ".yml", ".yaml", ".toml", ".sh",
    ".service", ".example", ".txt", ".env",
}


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    reason: str


RULES = [
    Rule("tailscale-ip", re.compile(r"\b100\.(?:\d{1,3}\.){2}\d{1,3}\b"), "Tailscale/private mesh IP"),
    Rule("internal-domain", re.compile(r"(?<!example)\.internal\b", re.I), "internal/private domain"),
    Rule("private-hostname", re.compile(r"\b(?:kasnet|clack-next\.kasnet|clack\.kasnet)\b", re.I), "private hostname/domain"),
    Rule("personal-agent-id", re.compile(r"agent://[a-z0-9-]+\.aaron\b", re.I), "personal agent namespace"),
    Rule("personal-human-id", re.compile(r"human://aaron\b", re.I), "personal human namespace"),
    Rule("live-wake-url", re.compile(r"https?://(?!127\.0\.0\.1|localhost|example\.invalid)[^\s)`'\"]+/wake\b", re.I), "non-example wake endpoint URL"),
    Rule("live-secret-path", re.compile(r"\bInfisical\b|(?<!secret-manager://example)/clack/(?:bootstrap-secret|agent-tokens)", re.I), "live secret-path vocabulary"),
]

PUBLIC_SCRUB_DOC = Path("specs/architecture/public-mirror-scrub-gate-v0.md")
SELF_ALLOWED_RULES = {"personal-agent-id", "personal-human-id"}


def is_text_candidate(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    if path.name == "check_public_scrub.py":
        return False
    if path == PUBLIC_SCRUB_DOC:
        return False
    if path.suffix in TEXT_SUFFIXES:
        return True
    if path.name.endswith(".env.example"):
        return True
    return False


def iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and is_text_candidate(path.relative_to(root)):
            yield path


def scan(root: Path):
    findings = []
    for path in iter_files(root):
        rel = path.relative_to(root)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for rule in RULES:
                if rel == PUBLIC_SCRUB_DOC and rule.name in SELF_ALLOWED_RULES:
                    continue
                if rule.pattern.search(line):
                    findings.append((str(rel), lineno, rule.name, rule.reason, line.strip()))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="scan Clack tree for public-mirror scrub findings")
    parser.add_argument("--root", default=str(ROOT), help="tree root to scan")
    parser.add_argument("--quiet", action="store_true", help="only print summary")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    findings = scan(root)
    if findings and not args.quiet:
        for file, line, name, reason, text in findings:
            print(f"{file}:{line}: {name}: {reason}: {text}")
    print(f"PUBLIC_SCRUB_FINDINGS={len(findings)}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
