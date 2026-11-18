#!/usr/bin/env python3
"""
Deterministic MANIFEST_SHA256.txt generator for The Reggae Shark Protocol (v1.3.2).

Reads the staged Git paths and blob bytes (or release-directory files outside Git) so Windows `core.autocrlf` working-tree line-ending conversions never corrupt hashes.
Also verifies that every text file uses LF line endings and has no UTF-8 BOM.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parent.parent

BINARY_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".zip", ".whl"}
EXCLUDED_PARTS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".lake", "build", "dist", "shark_protocol.egg-info"}


def _git_blob_bytes(repo_root: Path, rel_posix: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo_root), "show", f":{rel_posix}"],
        capture_output=True,
        check=True,
    ).stdout


def build_manifest(repo_root: Path = REPO_ROOT, use_git_head: bool = False) -> List[str]:
    if use_git_head:
        output = subprocess.check_output(["git", "-C", str(repo_root), "ls-files", "--cached", "-z"])
        paths = [Path(os.fsdecode(name)) for name in output.split(b"\0") if name]
    else:
        paths = [
            path.relative_to(repo_root) for path in repo_root.rglob("*")
            if path.is_file() and not any(
                part in EXCLUDED_PARTS or part.endswith(".egg-info")
                for part in path.relative_to(repo_root).parts
            )
        ]
    entries: List[str] = []
    for fpath in sorted(paths, key=lambda path: path.as_posix()):
        rel = fpath.as_posix()
        if rel == "MANIFEST_SHA256.txt":
            continue
        raw = _git_blob_bytes(repo_root, rel) if use_git_head else (repo_root / fpath).read_bytes()
        if fpath.suffix.lower() not in BINARY_EXTENSIONS:
            if raw.startswith(b"\xef\xbb\xbf"):
                raise RuntimeError(f"UTF-8 BOM detected in {rel}")
            if b"\r\n" in raw:
                raise RuntimeError(f"CRLF line endings detected in {rel}")
        digest = hashlib.sha256(raw).hexdigest()
        entries.append(f"{digest}  {rel}")
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare the manifest without rewriting it")
    args = parser.parse_args()
    has_git = (REPO_ROOT / ".git").exists()
    lines = build_manifest(REPO_ROOT, use_git_head=has_git)
    manifest_path = REPO_ROOT / "MANIFEST_SHA256.txt"
    expected = ("\n".join(lines) + "\n").encode("utf-8")
    if args.check:
        if not manifest_path.is_file() or manifest_path.read_bytes() != expected:
            print("Manifest differs. Stage release files and run python tools/make_manifest.py.", file=sys.stderr)
            return 1
        print(f"Verified {len(lines)} manifest entries")
        return 0
    manifest_path.write_bytes(expected)
    print(f"Wrote {len(lines)} SHA-256 entries to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
