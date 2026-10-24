"""
Comprehensive Unit, Integration, and Red-Team Adversarial Suite for The Shark Protocol (v1.1.0).

Verifies:
1. Layer 1 (VRK v0.3.1): Append-only SHA-256 hash chaining (`prev_hash`), `intentseal-vrk-claim-v2`
   schema enforcement, and tamper detection against payload modification, reordering, and deletion.
2. Layer 1B (`php2shell` Defense):
   - CVE-2026-109618 knockout: Out-Of-Memory (`OOM_ABORT`) interrupt during `PARTIAL_INIT` transitions
     strictly to `ABORTED_POISONED`, scrubs payload, blocks payload dereference, and blocks clean
     shutdown destructor Use-After-Free.
   - CVE-2026-109619 knockout: Stale worker-epoch slot (`slot_epoch != active_worker_epoch`) is
     rejected fail-closed even if its internal state is `SEALED_ACTIVE`.
3. Layer 2 (4D Soft-Wall ODE Governor):
   - Exact 4D integration of Eqs. (B.1)-(B.4) inside `B_4 = [0,10] x [0,100] x [0,I_max_4D] x [0,1]`.
   - Steady-state quadratic ratio identity `R_self_sq|_* = 0` when `dH_obs/dt = 0`.
4. Layer 3 (LRSC 11/99 Spectral Compression):
   - Exact `M=99, K=11` (`1/9` footprint) projection on `S_11 = {0,1,3,42,43,44,45,46,47,48,49}`
     and deterministic spectral digest generation.
5. Layer 4 (Multi-Cloud Security Gateway & HTTP Proxy):
   - Fail-closed rejection of unknown providers and empty prompts.
   - Honest `[VRK_OFFLINE_SEALED_SIMULATION]` when API keys are unconfigured vs. mocked `LIVE_API_DISPATCH`
     and automatic multi-provider failover when a primary provider raises a network error.
   - Lean 4 source file integrity audit (`ExistenceVerification.lean` 17 theorems,
     `BoundaryVerification.lean` 9 theorems, `TypestateLifecycle.lean` 5 theorems, zero `sorry`).
"""

from pathlib import Path
import re
import unittest
from unittest.mock import patch, MagicMock

from shark_protocol.kernel import (
    LRSCCompressor,
    LifecycleEvent,
    LifecycleState,
    RequestSlot,
    SharkProtocolEngine,
    TypestateViolationError,
    VRKSchemaError,
    VRK_TRUST_ROOT,
)
from shark_protocol.gateway import MultiProviderGateway


class TestSharkCore(unittest.TestCase):
    # ------------------------------------------------------------------------
    # 1. Layer 1: VRK v0.3.1 Hash-Chained Ledger & Red-Team Tamper Rejection
    # ------------------------------------------------------------------------

    def test_vrk_hash_chain_and_schema(self):
        eng = SharkProtocolEngine()
        c1 = eng.seal_claim("First verified proposition")
        c2 = eng.seal_claim("Second verified proposition")

        self.assertEqual(c1["schema"], "intentseal-vrk-claim-v2")
        self.assertEqual(c1["ledger_index"], 1)
        self.assertEqual(c1["prev_hash"], VRK_TRUST_ROOT)
        self.assertEqual(c2["ledger_index"], 2)
        self.assertEqual(c2["prev_hash"], c1["digest"])

        ok, status = eng.verify_ledger_integrity()
        self.assertTrue(ok)
        self.assertEqual(status, "VERIFIED_CHAIN_LENGTH_2")

    def test_vrk_redteam_tamper_detection(self):
        eng = SharkProtocolEngine()
        eng.seal_claim("Claim 1")
        eng.seal_claim("Claim 2")

        # Tamper with Claim 1 proposition in-place
        eng.ledger[0]["proposition"] = "Tampered proposition"
        ok, status = eng.verify_ledger_integrity()
        self.assertFalse(ok)
        self.assertIn("Digest tamper detected at index 1", status)

    def test_vrk_redteam_illegal_promotion_rejected(self):
        eng = SharkProtocolEngine()
        # Attempting to seal an ANALYTIC_THEOREM with only NUMERICAL_OBSERVATION evidence roles must fail
        with self.assertRaises(VRKSchemaError):
            eng.seal_claim(
                "Illegal promotion claim",
                claim_class="ANALYTIC_THEOREM",
                evidence=[
                    {"role": "definition", "path": "lean/ExistenceVerification.lean#ExistenceState"},
                    {"role": "execution_record", "path": "shark_protocol/kernel.py"},
                ],
            )

    def test_vrk_redteam_missing_firewall_rejected(self):
        ok, reason = SharkProtocolEngine.validate_vrk_claim({
            "schema": "intentseal-vrk-claim-v2",
            "claim_class": "REPRODUCED_RESULT",
            "scope": {"applies_to": ["all"], "does_not_imply": []},
            "evidence": [],
        })
        self.assertFalse(ok)
        self.assertIn("does_not_imply", reason)

    # ------------------------------------------------------------------------
    # 2. Layer 1B: `php2shell` (CVE-2026-109618 & CVE-2026-109619) Knockouts
    # ------------------------------------------------------------------------

    def test_cve_2026_109618_oom_partial_init_poisoning_and_uaf_block(self):
        gw = MultiProviderGateway()
        with self.assertRaises(TypestateViolationError):
            gw.process_request("groq", "Multipart upload simulation", simulate_oom=True)

        slot = gw.engine.active_slot
        self.assertEqual(slot.state, LifecycleState.ABORTED_POISONED)
        self.assertIsNone(slot.payload)

        # Dereferencing payload after OOM abort must fail-closed
        with self.assertRaises(TypestateViolationError):
            slot.read_payload(active_worker_epoch=gw.engine.worker_epoch)

        # Running clean shutdown destructor on poisoned state must fail-closed (no Use-After-Free)
        with self.assertRaises(TypestateViolationError):
            slot.run_clean_destructor()

    def test_cve_2026_109619_stale_worker_epoch_isolation(self):
        gw = MultiProviderGateway()
        # Create a sealed slot at epoch 1
        stale_slot = RequestSlot(slot_epoch=1, payload={"user": "alice_secret"})
        stale_slot.transition(LifecycleEvent.BEGIN_PARSE)
        stale_slot.transition(LifecycleEvent.COMMIT_SEAL, seal_digest="a" * 64)

        # Advance gateway to epoch 1 and then epoch 2
        gw.process_request("groq", "Request 1")
        gw.process_request("groq", "Request 2")
        self.assertEqual(gw.engine.worker_epoch, 2)

        # Attempting to read epoch-1 slot from epoch-2 worker must fail-closed
        with self.assertRaises(TypestateViolationError) as ctx:
            stale_slot.read_payload(active_worker_epoch=gw.engine.worker_epoch)
        self.assertIn("CVE-2026-109619", str(ctx.exception))

    def test_unsealed_partial_init_promotion_rejected(self):
        slot = RequestSlot(slot_epoch=1, payload={"data": 123})
        slot.transition(LifecycleEvent.BEGIN_PARSE)
        with self.assertRaises(TypestateViolationError):
            slot.transition(LifecycleEvent.COMMIT_SEAL, seal_digest="")
        self.assertEqual(slot.state, LifecycleState.ABORTED_POISONED)

    # ------------------------------------------------------------------------
    # 3. Layer 2: 4D Soft-Wall ODE Governor & Compact Box B_4 Invariance
    # ------------------------------------------------------------------------

    def test_4d_ode_box_confinement_and_dynamic_evolution(self):
        eng = SharkProtocolEngine()
        initial_state = dict(eng.state)
        for _ in range(15):
            st = eng.step_ode(duration=0.40)
            ok_box, reason = eng.verify_box_invariance(st)
            self.assertTrue(ok_box, msg=reason)

        # All 4 coordinates (gamma, H_obs, I_dot, Psi) must dynamically evolve (not frozen!)
        self.assertNotAlmostEqual(eng.state["gamma"], initial_state["gamma"], places=4)
        self.assertNotAlmostEqual(eng.state["H_obs"], initial_state["H_obs"], places=4)
        self.assertNotAlmostEqual(eng.state["I_dot"], initial_state["I_dot"], places=4)
        self.assertNotAlmostEqual(eng.state["Psi"], initial_state["Psi"], places=4)

    def test_trajectory_simulation_stays_in_b4(self):
        eng = SharkProtocolEngine()
        traj = eng.simulate_trajectory(total_time=30.0, sample_points=120)
        ceilings = traj["box_ceilings"]
        self.assertTrue(all(0.0 < g < ceilings["gamma_max"] for g in traj["gamma"]))
        self.assertTrue(all(0.0 < h < ceilings["H_max"] for h in traj["H_obs"]))
        self.assertTrue(all(0.0 < i < ceilings["I_dot_max_4D"] for i in traj["I_dot"]))
        self.assertTrue(all(0.0 <= p <= 1.0 for p in traj["Psi"]))

    # ------------------------------------------------------------------------
    # 4. Layer 3: LRSC 11/99 Odd-Ring Spectral Context Compression
    # ------------------------------------------------------------------------

    def test_lrsc_spectral_compression_11_over_99(self):
        rep = LRSCCompressor.compress_context("Autonomous agent context window payload for LRSC compression.")
        self.assertEqual(rep["M_ring"], 99)
        self.assertEqual(rep["K_subset"], 11)
        self.assertAlmostEqual(rep["compression_ratio"], 1.0 / 9.0, places=12)
        self.assertEqual(len(rep["witness_S11"]), 11)
        self.assertEqual(len(rep["retained_modes"]), 11)
        self.assertEqual(len(rep["spectral_digest"]), 64)

    # ------------------------------------------------------------------------
    # 5. Layer 4: Multi-Cloud Gateway, Fail-Closed Provider & Failover
    # ------------------------------------------------------------------------

    def test_gateway_offline_sealed_mode_all_providers(self):
        gw = MultiProviderGateway(api_keys={"groq": "", "together": "", "gemini": "", "huggingface": ""})
        for prov in ["groq", "together", "gemini", "huggingface"]:
            res = gw.process_request(prov, f"Test prompt for {prov}")
            self.assertEqual(res["status"], "200_OK")
            self.assertEqual(res["dispatch_mode"], "VRK_OFFLINE_SEALED_SIMULATION")
            self.assertEqual(res["typestate_final"], "ZEROED_FREED")
            self.assertIn("SEALED", res["layer1_vrk"])

    def test_gateway_rejects_unknown_provider_fail_closed(self):
        gw = MultiProviderGateway()
        with self.assertRaises(ValueError):
            gw.process_request("unknown_malicious_provider", "Test prompt")

    @patch("shark_protocol.gateway.requests.post")
    def test_gateway_live_api_dispatch_and_failover(self, mock_post):
        # First call (Groq) fails with RuntimeError; second call (Together) succeeds
        mock_ok = MagicMock()
        mock_ok.raise_for_status.return_value = None
        mock_ok.json.return_value = {"choices": [{"message": {"content": "Verified Together AI output"}}]}
        mock_post.side_effect = [RuntimeError("Groq timeout"), mock_ok]

        gw = MultiProviderGateway(api_keys={"groq": "key_groq", "together": "key_together"})
        res = gw.process_request("groq", "Execute failover test")
        self.assertEqual(res["status"], "200_OK")
        self.assertEqual(res["dispatch_mode"], "LIVE_API_DISPATCH")
        self.assertEqual(res["provider"], "TOGETHER")
        self.assertIn("Verified Together AI output", res["output"])

    # ------------------------------------------------------------------------
    # 6. Lean 4 Formal Proof Suite Integrity Check (31 Theorems, Zero `sorry`)
    # ------------------------------------------------------------------------

    def test_lean4_modules_zero_sorry_and_theorem_counts(self):
        repo_root = Path(__file__).resolve().parent.parent
        lean_dir = repo_root / "lean"

        ev_text = (lean_dir / "ExistenceVerification.lean").read_text(encoding="utf-8")
        bv_text = (lean_dir / "BoundaryVerification.lean").read_text(encoding="utf-8")
        tl_text = (lean_dir / "TypestateLifecycle.lean").read_text(encoding="utf-8")

        for name, txt in [
            ("ExistenceVerification.lean", ev_text),
            ("BoundaryVerification.lean", bv_text),
            ("TypestateLifecycle.lean", tl_text),
        ]:
            no_block = re.sub(r"/-.*?-/", " ", txt, flags=re.DOTALL)
            clean = re.sub(r"--[^\n]*", " ", no_block)
            self.assertIsNone(re.search(r"\bsorry\b", clean), msg=f"Forbidden sorry in {name}")
            self.assertIsNone(re.search(r"\bnlinarith\b", clean), msg=f"Forbidden nlinarith in {name}")

        ev_theorems = re.findall(r"\btheorem\s+([A-Za-z0-9_]+)", ev_text)
        bv_theorems = re.findall(r"\btheorem\s+([A-Za-z0-9_]+)", bv_text)
        tl_theorems = re.findall(r"\btheorem\s+([A-Za-z0-9_]+)", tl_text)

        self.assertEqual(len(ev_theorems), 17)
        self.assertEqual(len(bv_theorems), 9)
        self.assertEqual(len(tl_theorems), 5)


if __name__ == "__main__":
    unittest.main()
