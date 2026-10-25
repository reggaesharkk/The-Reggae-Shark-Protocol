#!/usr/bin/env python3
"""
CI & Local Axiom Gate Verifier (`tools/check_lean_axioms.py`)
Parses the output of `lake env lean lean/AxiomsCheck.lean` and verifies:
1. All 41 declared theorems across `lean/BoundaryVerification.lean` (9),
   `lean/ExistenceVerification.lean` (17), and `lean/TypestateLifecycle.lean` (15)
   are present in `lean/AxiomsCheck.lean` and in the captured Lean output.
2. Every printed axiom list is a subset of `{"propext", "Classical.choice", "Quot.sound"}`.
3. `sorryAx` or any custom axiom is strictly absent.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
ALLOWED_AXIOMS: Set[str] = {"propext", "Classical.choice", "Quot.sound"}

EXPECTED_MODULE_COUNTS: Dict[str, int] = {
    "lean/BoundaryVerification.lean": 9,
    "lean/ExistenceVerification.lean": 17,
    "lean/TypestateLifecycle.lean": 15,
}


def strip_lean_comments(text: str) -> str:
    no_block = re.sub(r"/-.*?-/", " ", text, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", " ", no_block)


def discover_declared_theorems(repo_root: Path = REPO_ROOT) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for rel_path, expected_count in EXPECTED_MODULE_COUNTS.items():
        full_path = repo_root / rel_path
        if not full_path.exists():
            raise FileNotFoundError(f"Missing Lean module: {full_path}")
        clean = strip_lean_comments(full_path.read_text(encoding="utf-8"))
        thms = re.findall(r"\b(?:theorem|lemma)\s+([A-Za-z0-9_]+)", clean)
        if len(thms) != expected_count:
            raise AssertionError(
                f"{rel_path} expected {expected_count} theorems, found {len(thms)}: {thms}"
            )
        out[rel_path] = thms
    return out


def verify_axioms_check_source(repo_root: Path = REPO_ROOT) -> List[str]:
    declared_map = discover_declared_theorems(repo_root)
    ax_file = repo_root / "lean/AxiomsCheck.lean"
    if not ax_file.exists():
        raise FileNotFoundError(f"Missing {ax_file}")
    clean = strip_lean_comments(ax_file.read_text(encoding="utf-8"))
    printed = re.findall(r"#print\s+axioms\s+([A-Za-z0-9_.]+)", clean)
    short_printed = [p.split(".")[-1] for p in printed]
    expected_all = [
        t for rel in ("lean/BoundaryVerification.lean", "lean/ExistenceVerification.lean", "lean/TypestateLifecycle.lean")
        for t in declared_map[rel]
    ]
    if len(short_printed) != 41 or set(short_printed) != set(expected_all):
        raise AssertionError(
            f"lean/AxiomsCheck.lean #print axioms mismatch: count={len(short_printed)}, "
            f"missing={set(expected_all) - set(short_printed)}"
        )
    return expected_all


def verify_lean_axioms_output(raw_output: str, repo_root: Path = REPO_ROOT) -> Dict[str, Set[str]]:
    expected_all = verify_axioms_check_source(repo_root)
    if "sorryAx" in raw_output:
        raise AssertionError("Forbidden 'sorryAx' detected in Lean axiom output!")

    depends_re = re.compile(r"^'([^']+)'\s+depends on axioms:\s*\[([^\]]*)\]\s*$")
    no_axioms_re = re.compile(r"^'([^']+)'\s+does not depend on any axioms\s*$")

    parsed: Dict[str, Set[str]] = {}
    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m_dep = depends_re.match(line)
        if m_dep:
            thm_full, ax_list_str = m_dep.group(1), m_dep.group(2)
            thm_short = thm_full.split(".")[-1]
            axioms = {a.strip() for a in ax_list_str.split(",") if a.strip()}
            disallowed = axioms - ALLOWED_AXIOMS
            if disallowed:
                raise AssertionError(
                    f"Theorem '{thm_full}' uses disallowed axioms: {sorted(disallowed)}"
                )
            parsed[thm_short] = axioms
            continue
        m_none = no_axioms_re.match(line)
        if m_none:
            thm_full = m_none.group(1)
            thm_short = thm_full.split(".")[-1]
            parsed[thm_short] = set()

    missing = set(expected_all) - set(parsed.keys())
    if missing or len(parsed) != len(expected_all):
        raise AssertionError(
            f"Axiom output count mismatch: verified {len(parsed)}/{len(expected_all)} theorems; "
            f"missing={sorted(missing)}"
        )
    return parsed


def main() -> int:
    verify_axioms_check_source(REPO_ROOT)
    if len(sys.argv) > 1 and sys.argv[1] == "--source-only":
        print("AXIOMS_SOURCE_CHECK_OK: 41/41 theorems registered in lean/AxiomsCheck.lean")
        return 0
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        raw = Path(sys.argv[1]).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()
    parsed = verify_lean_axioms_output(raw, REPO_ROOT)
    print(
        f"AXIOMS_OUTPUT_VERIFIED: {len(parsed)}/41 theorems checked; "
        f"all axioms subset of {sorted(ALLOWED_AXIOMS)} with 0 sorryAx."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
