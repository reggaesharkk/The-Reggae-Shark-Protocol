"""
Command-Line Interface for The Shark Protocol (v1.1.0).
Supports:
- `shark-protocol --cli`            : Run a full 4-layer execution & verification audit
- `shark-protocol --audit-php2shell`: Run the CVE-2026-109618 / CVE-2026-109619 typestate knockout demo
- `shark-protocol --serve`          : Start the local HTTP gateway server on http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import json
import sys
from .gateway import MultiProviderGateway, run_http_gateway
from .kernel import LifecycleEvent, RequestSlot, TypestateViolationError


def run_php2shell_audit(gw: MultiProviderGateway) -> None:
    print("\n--- [LAYER 1B] php2shell (CVE-2026-109618 & CVE-2026-109619) Knockout Audit ---")
    # Test 1: CVE-2026-109618 OOM interrupt during PARTIAL_INIT
    try:
        gw.process_request("groq", "Large multipart upload simulation", simulate_oom=True)
    except TypestateViolationError as exc:
        slot = gw.engine.active_slot
        print(f"  [PASS] CVE-2026-109618 OOM Abort Blocked     : {exc}")
        print(f"         Slot state after OOM interrupt        : {slot.state.value} (payload={slot.payload})")
        try:
            slot.run_clean_destructor()
        except TypestateViolationError as uaf_exc:
            print(f"  [PASS] CVE-2026-109618 Shutdown UAF Blocked  : {uaf_exc}")

    # Test 2: CVE-2026-109619 Stale Global Worker State across epochs
    stale_slot = RequestSlot(slot_epoch=gw.engine.worker_epoch, payload={"secret": "stale_session"})
    stale_slot.transition(LifecycleEvent.BEGIN_PARSE)
    stale_slot.transition(LifecycleEvent.COMMIT_SEAL, seal_digest="deadbeef" * 8)
    # Advance worker to next epoch
    gw.process_request("groq", "Next worker request on fresh epoch")
    try:
        stale_slot.read_payload(active_worker_epoch=gw.engine.worker_epoch)
    except TypestateViolationError as stale_exc:
        print(f"  [PASS] CVE-2026-109619 Stale Epoch Blocked   : {stale_exc}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="The Shark Protocol Security Gateway v1.1.0")
    parser.add_argument("--cli", action="store_true", help="Run 4-layer verified execution demo")
    parser.add_argument("--audit-php2shell", action="store_true", help="Run php2shell typestate & epoch knockout audit")
    parser.add_argument("--serve", action="store_true", help="Launch HTTP Security Gateway on http://127.0.0.1:8000")
    parser.add_argument("--port", type=int, default=8000, help="Port for --serve (default: 8000)")
    args = parser.parse_args(argv)

    if args.serve:
        run_http_gateway(port=args.port)
        return 0

    gw = MultiProviderGateway()
    print("=== The Shark Protocol Security Gateway v1.1.0 (Ironclad Edition) ===")
    print("Active Backends: Groq | Together AI | Google Gemini | Hugging Face\n")

    res = gw.process_request("groq", "Verify autonomous agent transaction under 4D soft-wall ODE bounds.")
    print("Status          :", res["status"])
    print("Dispatch Mode   :", res["dispatch_mode"])
    print("Provider        :", f"{res['provider']} (Model: {res['target_model']})")
    print("Worker Epoch    :", f"{res['worker_epoch']} (Final Typestate: {res['typestate_final']})")
    print("Layer 1 (VRK)   :", res["layer1_vrk"])
    print("Layer 2 (4D ODE):", json.dumps(res["layer2_governor"]))
    print(
        "Layer 3 (LRSC)  :",
        f"Footprint={res['layer3_lrsc']['footprint_fraction']} | "
        f"Rel L2 Err={res['layer3_lrsc']['relative_l2_error']} | "
        f"Digest={res['layer3_lrsc']['spectral_digest'][:12]}...",
    )
    print("Response        :", res["output"])

    if args.audit_php2shell or args.cli or len(sys.argv) == 1:
        run_php2shell_audit(gw)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
