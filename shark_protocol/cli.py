"""
Command-Line Interface for The Reggae Shark Protocol (`shark_protocol/cli.py`)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Canonical DOI: 10.5281/zenodo.23620074
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .gateway import MultiProviderGateway, run_http_gateway_server


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shark-protocol",
        description="The Reggae Shark Protocol (v1.1.2) — Verifiable AI Execution Kernel & Multi-Cloud Gateway",
    )
    parser.add_argument("--cli", action="store_true", help="Run interactive or single-shot CLI verification pipeline")
    parser.add_argument("--prompt", type=str, default="Verify 4D soft-wall ODE & LRSC 11/99 state", help="Prompt text to process")
    parser.add_argument("--provider", type=str, default="groq", help="Target provider (groq, together, gemini, huggingface)")
    parser.add_argument("--audit-lifecycle", "--audit-php2shell", dest="audit_lifecycle", action="store_true", help="Run formal typestate lifecycle, worker-epoch, and red-team self-audit")
    parser.add_argument("--serve", action="store_true", help="Launch local loopback HTTP gateway server")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="HTTP bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP bind port (default: 8000)")

    args = parser.parse_args(argv)
    gw = MultiProviderGateway()

    if args.serve:
        run_http_gateway_server(host=args.host, port=args.port)
        return 0

    if args.audit_lifecycle:
        audit_report = gw.engine.run_lifecycle_and_redteam_audit()
        print(json.dumps(audit_report, indent=2, sort_keys=True))
        if not audit_report["all_checks_passed"]:
            return 1

    if args.cli or not args.audit_lifecycle:
        res = gw.process_request(prompt=args.prompt, provider=args.provider)
        ok, chain_msg = gw.engine.verify_ledger_integrity()
        print(json.dumps({
            "status": res["status"],
            "dispatch_mode": res["dispatch_mode"],
            "provider": res["provider"],
            "worker_epoch": res["worker_epoch"],
            "lrsc_ratio": res["lrsc"]["compression_ratio_exact"],
            "lrsc_sha256": res["lrsc"]["lrsc_sha256"],
            "vrk_digest": res["vrk_seal"]["digest"],
            "vrk_chain_status": chain_msg,
            "ode_state": res["ode_state"],
        }, indent=2, sort_keys=True))
        return 0 if ok else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
