#!/usr/bin/env python3
"""
CI & Local Verification Gate for Lean 4 Theorems and Transition Table (`tools/check_lean_axioms.py`).

Checks:
1. Comment-stripped source of all 3 Lean modules (`BoundaryVerification.lean`: 9,
   `ExistenceVerification.lean`: 17, `TypestateLifecycle.lean`: 16) contains zero `sorry`,
   `sorryAx`, `axiom`, or `nlinarith`, and declares all 42 expected theorem names.
2. `lean/AxiomsCheck.lean` contains `#print axioms <thm>` for all 42 theorems.
3. When given the stdout file from `lake env lean lean/AxiomsCheck.lean`, verifies that all 42
   theorems appear in the output and that every theorem's axioms are a subset of
   `{"propext", "Classical.choice", "Quot.sound"}` (or `does not depend on any axioms`) with zero `sorryAx`.
4. When invoked with `--check-transition-table <eval_stdout_file>`, extracts the JSON emitted by
   `#eval dumpTransitionTableJson` in `lake env lean lean/TypestateLifecycle.lean` and diffs it
   against `data/lean_transition_table.json` so the committed table can never drift from Lean.
"""
from __future__ import annotations

import json
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

EXPECTED_COUNTS = {
    "lean/BoundaryVerification.lean": 9,
    "lean/ExistenceVerification.lean": 17,
    "lean/TypestateLifecycle.lean": 16,
}
TOTAL_EXPECTED_THEOREMS = 42


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
    all_theorems: List[str] = []
    for rel, count in EXPECTED_COUNTS.items():
        found = decl_map[rel]
        if len(found) != count:
            raise AssertionError(f"{rel}: expected {count} theorems, found {len(found)}")
        all_theorems.extend(found)

    ax_path = repo_root / "lean" / "AxiomsCheck.lean"
    if not ax_path.exists():
        raise AssertionError("Missing lean/AxiomsCheck.lean")
    ax_clean = strip_lean_comments(ax_path.read_text(encoding="utf-8"))
    printed = [m.split(".")[-1] for m in re.findall(r"#print\s+axioms\s+([A-Za-z0-9_.']+)", ax_clean)]
    if sorted(printed) != sorted(all_theorems) or len(printed) != TOTAL_EXPECTED_THEOREMS:
        raise AssertionError(
            f"lean/AxiomsCheck.lean #print axioms mismatch: expected {TOTAL_EXPECTED_THEOREMS} theorems, got {len(printed)}"
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
    if len(parsed) != TOTAL_EXPECTED_THEOREMS:
        raise AssertionError(f"Expected {TOTAL_EXPECTED_THEOREMS} theorem axiom records, got {len(parsed)}")
    return parsed


def verify_lean_transition_table_eval(
    eval_stdout_text: str,
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Dict[str, str]]:
    """
    Parse the JSON string emitted by `#eval dumpTransitionTableJson` in
    `lake env lean lean/TypestateLifecycle.lean` and verify that it matches
    `data/lean_transition_table.json` on all 30 state-event transitions.
    """
    committed_path = repo_root / "data" / "lean_transition_table.json"
    if not committed_path.exists():
        raise AssertionError("Missing data/lean_transition_table.json")
    committed_table = json.loads(committed_path.read_text(encoding="utf-8"))

    parsed_eval = None
    for raw_line in eval_stdout_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('"') and line.endswith('"'):
            try:
                unquoted = json.loads(line)
                if isinstance(unquoted, str) and unquoted.startswith("{"):
                    cand = json.loads(unquoted)
                    if isinstance(cand, dict) and "UNINIT" in cand:
                        parsed_eval = cand
                        break
            except Exception:
                pass
        if line.startswith("{") and line.endswith("}"):
            try:
                cand = json.loads(line)
                if isinstance(cand, dict) and "UNINIT" in cand:
                    parsed_eval = cand
                    break
            except Exception:
                pass

    if parsed_eval is None:
        raise AssertionError("Could not find #eval dumpTransitionTableJson output in Lean stdout.")
    if parsed_eval != committed_table:
        raise AssertionError(
            f"Lean #eval transition table drifted from data/lean_transition_table.json:\n"
            f"  eval={json.dumps(parsed_eval, sort_keys=True)}\n"
            f"  file={json.dumps(committed_table, sort_keys=True)}"
        )
    return parsed_eval


def main(argv: List[str]) -> int:
    expected = verify_axioms_check_source(REPO_ROOT)
    if len(argv) >= 3 and argv[1] == "--check-transition-table":
        eval_path = Path(argv[2])
        eval_text = eval_path.read_text(encoding="utf-8")
        verify_lean_transition_table_eval(eval_text, REPO_ROOT)
        print("OK: Lean #eval transition table matches committed data/lean_transition_table.json (30/30 entries).")
        return 0
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
