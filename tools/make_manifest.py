#!/usr/bin/env python3
"""
Deterministic Manifest Generator (`tools/make_manifest.py`)
Generates `MANIFEST_SHA256.txt` from committed Git blobs (`git show HEAD:<path>`) when run
inside a Git repository (preventing working-tree CRLF contamination), or from clean LF
files when run on an exported archive, and verifies every entry.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_NAME = "MANIFEST_SHA256.txt"


def _git_tracked_files(repo_root: Path) -> List[str]:
    res = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted(
        line.strip().replace("\\", "/")
        for line in res.stdout.splitlines()
        if line.strip() and line.strip() != MANIFEST_NAME
    )


def _git_blob_bytes(repo_root: Path, rel_path: str) -> bytes:
    res = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"HEAD:{rel_path}"],
        capture_output=True,
        check=True,
    )
    return res.stdout


def build_manifest(repo_root: Path = REPO_ROOT, use_git_head: bool = True) -> List[str]:
    git_dir = repo_root / ".git"
    lines: List[str] = []
    if use_git_head and git_dir.exists():
        paths = _git_tracked_files(repo_root)
        for rel in paths:
            raw = _git_blob_bytes(repo_root, rel)
            digest = hashlib.sha256(raw).hexdigest()
            lines.append(f"{digest}  {rel}")
    else:
        all_files = sorted(
            p for p in repo_root.rglob("*")
            if p.is_file()
            and p.name != MANIFEST_NAME
            and ".git" not in p.parts
            and "__pycache__" not in p.parts
            and not p.name.endswith(".pyc")
        )
        for p in all_files:
            rel = str(p.relative_to(repo_root)).replace("\\", "/")
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            lines.append(f"{digest}  {rel}")
    manifest_path = repo_root / MANIFEST_NAME
    manifest_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    manifest_path.write_bytes(manifest_bytes)
    return lines


def verify_manifest(repo_root: Path = REPO_ROOT) -> int:
    manifest_path = repo_root / MANIFEST_NAME
    raw_lines = [
        line.strip()
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for line in raw_lines:
        expected_hash, rel = line.split("  ", 1)
        f_path = repo_root / rel
        if not f_path.exists():
            raise FileNotFoundError(f"Manifest entry missing on disk: {rel}")
        actual = hashlib.sha256(f_path.read_bytes()).hexdigest()
        if actual != expected_hash:
            raise AssertionError(f"SHA-256 mismatch for {rel}: expected {expected_hash}, got {actual}")
    return len(raw_lines)


if __name__ == "__main__":
    use_head = "--from-worktree" not in sys.argv
    lines = build_manifest(REPO_ROOT, use_git_head=use_head)
    count = verify_manifest(REPO_ROOT)
    print(f"MANIFEST_OK: {count} files hashed and verified in {MANIFEST_NAME}")
