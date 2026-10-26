#!/usr/bin/env python3
"""
Deterministic MANIFEST_SHA256.txt generator for The Reggae Shark Protocol (v1.3.2).

Reads exact staged git blob bytes via `git show :<path>` (or `git show HEAD:<path>` / disk bytes
if outside git) so Windows `core.autocrlf` working-tree line-ending conversions never corrupt hashes.
Also verifies that every text file uses LF line endings and has no UTF-8 BOM.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parent.parent

BINARY_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".zip", ".whl"}
EXCLUDED_NAMES = {"MANIFEST_SHA256.txt"}
EXCLUDED_PARTS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".lake", "build", "dist", "shark_protocol.egg-info"}


def _git_blob_bytes(repo_root: Path, rel_posix: str) -> bytes:
    res_idx = subprocess.run(
        ["git", "-C", str(repo_root), "show", f":{rel_posix}"],
        capture_output=True,
        check=False,
    )
    if res_idx.returncode == 0:
        return res_idx.stdout
    res_head = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"HEAD:{rel_posix}"],
        capture_output=True,
        check=False,
    )
    if res_head.returncode == 0:
        return res_head.stdout
    return (repo_root / rel_posix).read_bytes()


def build_manifest(repo_root: Path = REPO_ROOT, use_git_head: bool = False) -> List[str]:
    entries: List[str] = []
    for fpath in sorted(repo_root.rglob("*")):
        if not fpath.is_file():
            continue
        rel = fpath.relative_to(repo_root).as_posix()
        if fpath.name in EXCLUDED_NAMES:
            continue
        if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in fpath.relative_to(repo_root).parts):
            continue
        raw = _git_blob_bytes(repo_root, rel) if use_git_head else fpath.read_bytes()
        if fpath.suffix.lower() not in BINARY_EXTENSIONS:
            if raw.startswith(b"\xef\xbb\xbf"):
                raise RuntimeError(f"UTF-8 BOM detected in {rel}")
            if b"\r\n" in raw:
                raise RuntimeError(f"CRLF line endings detected in {rel}")
        digest = hashlib.sha256(raw).hexdigest()
        entries.append(f"{digest}  {rel}")
    return entries


def main() -> int:
    has_git = (REPO_ROOT / ".git").exists()
    lines = build_manifest(REPO_ROOT, use_git_head=has_git)
    manifest_path = REPO_ROOT / "MANIFEST_SHA256.txt"
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {len(lines)} SHA-256 entries to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
