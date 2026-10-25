#!/usr/bin/env python3
"""
CI & Local Gate: Verify all 41 Lean 4 theorems across BoundaryVerification.lean (9),
ExistenceVerification.lean (17), and TypestateLifecycle.lean (15).

Checks:
1. Comment-stripped source of all 3 Lean modules contains zero `sorry`, `sorryAx`, `axiom`, or `nlinarith`,
   and declares all 41 expected theorem names.
2. `lean/AxiomsCheck.lean` contains `#print axioms <thm>` for all 41 theorems.
3. When given the stdout file from `lake env lean lean/AxiomsCheck.lean`, verifies that all 41
   theorems appear in the output and that every theorem's axioms are a subset of
   `{"propext", "Classical.choice", "Quot.sound"}` (or `does not depend on any axioms`) with zero `sorryAx`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
ALLOWED_AXIOMS: Set[str] = {"propext", "Classical.choice", "Quot.sound"}

LEAN_MODULES = (
    "lean/BoundaryVerification.lean",
    "lean/ExistenceVerification.lean",
    "lean/TypestateLifecycle.lean",
)


def strip_lean_comments(text: str) -> str:
    text = re.sub(r"/-.*?-/", " ", text, flags=re.DOTALL)
    text = re.sub(r"--[^\n]*", " ", text)
    return text


def discover_declared_theorems(repo_root: Path = REPO_ROOT) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for rel in LEAN_MODULES:
        p = repo_root / rel
        if not p.exists():
            raise AssertionError(f"Missing Lean module: {rel}")
        clean = strip_lean_comments(p.read_text(encoding="utf-8"))
        for forbidden in ("sorry", "sorryAx", "axiom", "nlinarith"):
            if re.search(rf"\b{forbidden}\b", clean):
                raise AssertionError(f"Forbidden token '{forbidden}' found in {rel}")
        thms = re.findall(r"\btheorem\s+([A-Za-z0-9_']+)", clean)
        out[rel] = thms
    return out


def verify_axioms_check_source(repo_root: Path = REPO_ROOT) -> List[str]:
    decl_map = discover_declared_theorems(repo_root)
    expected_counts = {
        "lean/BoundaryVerification.lean": 9,
        "lean/ExistenceVerification.lean": 17,
        "lean/TypestateLifecycle.lean": 15,
    }
    all_theorems: List[str] = []
    for rel, count in expected_counts.items():
        found = decl_map[rel]
        if len(found) != count:
            raise AssertionError(f"{rel}: expected {count} theorems, found {len(found)}")
        all_theorems.extend(found)

    ax_path = repo_root / "lean" / "AxiomsCheck.lean"
    if not ax_path.exists():
        raise AssertionError("Missing lean/AxiomsCheck.lean")
    ax_clean = strip_lean_comments(ax_path.read_text(encoding="utf-8"))
    printed = [m.split(".")[-1] for m in re.findall(r"#print\s+axioms\s+([A-Za-z0-9_.']+)", ax_clean)]
    if sorted(printed) != sorted(all_theorems) or len(printed) != 41:
        raise AssertionError(
            f"lean/AxiomsCheck.lean #print axioms mismatch: expected 41 theorems, got {len(printed)}"
        )
    return all_theorems


def verify_lean_axioms_output(stdout_text: str, repo_root: Path = REPO_ROOT) -> Dict[str, Set[str]]:
    expected = verify_axioms_check_source(repo_root)
    if "sorryAx" in stdout_text:
        raise AssertionError("CRITICAL: sorryAx detected in Lean #print axioms output!")
    dep_pattern = re.compile(r"^'([^']+)'\s+depends on axioms:\s*\[(.*)\]\s*$", re.MULTILINE)
    no_ax_pattern = re.compile(r"^'([^']+)'\s+does not depend on any axioms\s*$", re.MULTILINE)

    parsed: Dict[str, Set[str]] = {}
    for match in dep_pattern.finditer(stdout_text):
        thm_name = match.group(1).strip().split(".")[-1]
        raw_axioms = match.group(2).strip()
        axioms = {a.strip() for a in raw_axioms.split(",") if a.strip()} if raw_axioms else set()
        if "sorryAx" in axioms:
            raise AssertionError(f"Theorem '{thm_name}' depends on sorryAx")
        disallowed = axioms - ALLOWED_AXIOMS
        if disallowed:
            raise AssertionError(f"Theorem '{thm_name}' uses disallowed axioms: {sorted(disallowed)}")
        parsed[thm_name] = axioms

    for match in no_ax_pattern.finditer(stdout_text):
        thm_name = match.group(1).strip().split(".")[-1]
        parsed[thm_name] = set()

    missing = set(expected) - set(parsed.keys())
    if missing:
        raise AssertionError(f"Missing #print axioms output for {len(missing)} theorems: {sorted(missing)}")
    if len(parsed) != 41:
        raise AssertionError(f"Expected 41 theorem axiom records, got {len(parsed)}")
    return parsed


def main(argv: List[str]) -> int:
    expected = verify_axioms_check_source(REPO_ROOT)
    if len(argv) >= 2 and argv[1] != "--source-only":
        out_path = Path(argv[1])
        stdout_text = out_path.read_text(encoding="utf-8")
        verify_lean_axioms_output(stdout_text, REPO_ROOT)
        print(f"OK: verified all {len(expected)} theorems and their Lean #print axioms outputs.")
    else:
        print(f"OK: verified {len(expected)} theorems in lean/AxiomsCheck.lean (source-only mode).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
