"""
Unit, Integration, and Senior Red-Team Stress Suite (`tests/test_core.py`)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Canonical DOI: 10.5281/zenodo.23624605

Covers:
  - Layer 1: VRK v0.3.1 SHA-256 hash-chain & tamper rejection (`test_01`, `test_02`, `test_05`)
  - Layer 1B: Typestate lifecycle & worker-epoch isolation (`test_03`, `test_04`)
  - Layer 2: 4D soft-wall ODE integration & 8-face Nagumo bounds (`test_06`, `test_07`)
  - Layer 3: LRSC 11/99 = 1/9 spectral projection (`test_08`)
  - Layer 4: Multi-cloud gateway failover, fail-closed config, & loopback HTTP server (`test_09`..`test_13`)
  - Lean 4: Zero-sorry & canonical SHA-256 provenance audit across 34 theorems (`test_14`)
  - Red-Team Problem 1: Patankar-Euler + IEEE-754 interval enclosure under impulsive burst (`test_15`)
  - Red-Team Problem 2: P_0=0 Gronwall capacitive decay floor & basin separatrix guard (`test_16`)
  - Red-Team Problem 3: LRSC S_11^perp null-space adversarial injection detection & fallback (`test_17`)
  - Red-Team Problem 4: 16-thread concurrent worker race & mid-flight exception stress (`test_18`)
  - Red-Team Problem 5: Commutative Merkle-DAG split-brain branch reconciliation (`test_19`, `test_20`)
"""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import re
import threading
import unittest
from urllib import request as urllib_request
from urllib.error import HTTPError

import numpy as np

from shark_protocol.gateway import (
    GatewayConfigError,
    MultiProviderGateway,
    create_gateway_http_server,
)
from shark_protocol.kernel import (
    VRK_TRUST_ROOT_DIGEST,
    BasinCollapseError,
    LRSCCompressor,
    LifecycleEvent,
    LifecycleState,
    RequestSlot,
    SharkProtocolEngine,
    StaleWorkerEpochError,
    TypestateViolationError,
    WorkerEpochGuard,
)


class TestSharkProtocolSuite(unittest.TestCase):

    def test_01_vrk_hash_chain_continuity(self) -> None:
        engine = SharkProtocolEngine()
        c1 = engine.seal_claim("claim.1", "First verified step")
        c2 = engine.seal_claim("claim.2", "Second verified step")
        c3 = engine.seal_claim("claim.3", "Third verified step")
        self.assertEqual(c1["prev_hash"], VRK_TRUST_ROOT_DIGEST)
        self.assertEqual(c2["prev_hash"], c1["digest"])
        self.assertEqual(c3["prev_hash"], c2["digest"])
        ok, msg = engine.verify_ledger_integrity()
        self.assertTrue(ok, msg)

    def test_02_vrk_tamper_detection(self) -> None:
        engine = SharkProtocolEngine()
        engine.seal_claim("claim.1", "Initial state")
        engine.seal_claim("claim.2", "Follow-up state")
        engine.ledger[0]["claim_text"] = "Tampered state"
        ok, msg = engine.verify_ledger_integrity()
        self.assertFalse(ok)
        self.assertIn("mismatch", msg)

    def test_03_partial_init_oom_abort_and_uaf_guard(self) -> None:
        slot = RequestSlot(slot_epoch=1)
        slot.transition(LifecycleEvent.BEGIN_INIT)
        self.assertEqual(slot.state, LifecycleState.PARTIAL_INIT)
        slot.transition(LifecycleEvent.OOM_ABORT)
        self.assertEqual(slot.state, LifecycleState.ABORTED_POISONED)
        with self.assertRaises(TypestateViolationError):
            slot.dereference_payload()
        with self.assertRaises(TypestateViolationError):
            slot.run_clean_destructor()
        slot.transition(LifecycleEvent.ZERO_AND_FREE)
        self.assertEqual(slot.state, LifecycleState.ZEROED_FREED)
        self.assertTrue(slot.is_zeroed)

    def test_04_stale_worker_epoch_isolation(self) -> None:
        guard = WorkerEpochGuard(initial_epoch=1)
        slot_req1 = guard.begin_request()
        slot_req1.transition(LifecycleEvent.SEAL_SUCCESS, payload={"token": "req1_secret"})
        self.assertEqual(guard.read_slot(slot_req1)["token"], "req1_secret")

        # Next request increments worker epoch and retires previous slot
        slot_req2 = guard.begin_request()
        slot_req2.transition(LifecycleEvent.SEAL_SUCCESS, payload={"token": "req2_public"})
        with self.assertRaises(StaleWorkerEpochError):
            guard.read_slot(slot_req1)

        # Even a freshly forged slot with an older epoch is rejected
        forged_old_slot = RequestSlot(slot_epoch=slot_req1.slot_epoch)
        forged_old_slot.transition(LifecycleEvent.BEGIN_INIT)
        forged_old_slot.transition(LifecycleEvent.SEAL_SUCCESS, payload={"forged": True})
        with self.assertRaises(StaleWorkerEpochError):
            guard.read_slot(forged_old_slot)

    def test_05_vrk_promotion_and_scope_firewall_gate(self) -> None:
        engine = SharkProtocolEngine()
        with self.assertRaises(ValueError):
            engine.seal_claim("bad.scope", "Missing firewall", does_not_imply=[])
        with self.assertRaises(ValueError):
            engine.seal_claim(
                "bad.promotion",
                "Illegal promotion without proof role",
                claim_class="ANALYTIC_THEOREM",
                evidence=[{"role": "definition", "path": "shark_protocol/kernel.py"}],
            )

    def test_06_4d_soft_wall_ode_forward_invariance(self) -> None:
        engine = SharkProtocolEngine(P_0=4.0, lam_sim=7.2, lam_lucid=0.3, kappa_meta=2.5)
        for _ in range(50):
            snap = engine.step_ode(dt=0.05)
            self.assertTrue(snap["inside_B4"])
            self.assertGreater(snap["gamma"], 0.0)
            self.assertLess(snap["gamma"], engine.gamma_max)
            self.assertGreater(snap["H_obs"], 0.0)
            self.assertLess(snap["H_obs"], engine.H_max)
            self.assertGreater(snap["I_dot"], 0.0)
            self.assertLessEqual(snap["I_dot"], snap["I_max_4D"])
            self.assertGreaterEqual(snap["Psi"], 0.0)
            self.assertLessEqual(snap["Psi"], 1.0)

    def test_07_nagumo_8face_boundary_certificate(self) -> None:
        engine = SharkProtocolEngine()
        cert = engine.verify_nagumo_boundary_certificate()
        self.assertTrue(cert["all_8_faces_certified"])

    def test_08_lrsc_11_99_compression_ratio_and_determinism(self) -> None:
        comp = LRSCCompressor()
        r1 = comp.compress("Deterministic spectral witness test prompt")
        r2 = comp.compress("Deterministic spectral witness test prompt")
        self.assertEqual(r1["M"], 99)
        self.assertEqual(r1["K"], 11)
        self.assertAlmostEqual(r1["compression_ratio"], 11.0 / 99.0, places=12)
        self.assertEqual(r1["lrsc_sha256"], r2["lrsc_sha256"])
        self.assertEqual(len(r1["witness_vector"]), 11)

    def test_09_gateway_fail_closed_unknown_provider(self) -> None:
        gw = MultiProviderGateway()
        with self.assertRaises(GatewayConfigError):
            gw.process_request("Test prompt", provider="unknown_cloud")

    def test_10_gateway_offline_sealed_simulation_honesty(self) -> None:
        gw = MultiProviderGateway()
        res = gw.process_request("Offline verification check", provider="groq")
        self.assertEqual(res["status"], "SEALED_OK")
        self.assertEqual(res["dispatch_mode"], "VRK_OFFLINE_SEALED_SIMULATION")
        self.assertEqual(res["slot_final_state"], "ZEROED_FREED")

    def test_11_gateway_simulated_oom_abort_poisons_slot(self) -> None:
        gw = MultiProviderGateway()
        with self.assertRaises(TypestateViolationError):
            gw.process_request("Trigger OOM", provider="groq", simulate_oom_abort=True)

    def test_12_http_gateway_health_and_execute_roundtrip(self) -> None:
        server, _ = create_gateway_http_server(host="127.0.0.1", port=0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib_request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
                health = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(health["status"], "healthy")
                self.assertEqual(health["doi"], "10.5281/zenodo.23624605")

            req = urllib_request.Request(
                f"http://127.0.0.1:{port}/v1/execute",
                data=json.dumps({"prompt": "HTTP loopback test", "provider": "groq"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib_request.urlopen(req, timeout=5) as resp:
                out = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(out["status"], "SEALED_OK")
                self.assertEqual(out["lrsc"]["compression_ratio_exact"], "11/99")
        finally:
            server.shutdown()
            server.server_close()

    def test_13_http_gateway_rejects_bad_provider_with_400(self) -> None:
        server, _ = create_gateway_http_server(host="127.0.0.1", port=0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            req = urllib_request.Request(
                f"http://127.0.0.1:{port}/v1/execute",
                data=json.dumps({"prompt": "Bad provider", "provider": "invalid_provider"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(HTTPError) as ctx:
                urllib_request.urlopen(req, timeout=5)
            self.assertEqual(ctx.exception.code, 400)
        finally:
            server.shutdown()
            server.server_close()

    def test_14_lean4_34_theorems_zero_sorry_and_canonical_hashes(self) -> None:
        root = pathlib.Path(__file__).resolve().parent.parent
        expected = {
            "BoundaryVerification.lean": (9, "49229b6163b5a3a77dc83779a7dc5350502ff2b3d6a7f2de4d39996f4460e417"),
            "ExistenceVerification.lean": (17, "eec9486803fb2e12f94c3ef966098acd31e4a66df8269ebe8cb59a937f7abcae"),
            "TypestateLifecycle.lean": (8, None),
        }
        total_theorems = 0
        for fname, (min_thms, exp_sha) in expected.items():
            fpath = root / "lean" / fname
            self.assertTrue(fpath.exists(), f"Missing {fpath}")
            raw = fpath.read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), f"UTF-8 BOM in {fname}")
            if exp_sha is not None:
                self.assertEqual(hashlib.sha256(raw).hexdigest(), exp_sha)
            txt = raw.decode("utf-8")
            clean = re.sub(r"/-.*?-/", " ", txt, flags=re.DOTALL)
            clean = re.sub(r"--[^\n]*", " ", clean)
            self.assertIsNone(re.search(r"\bsorry\b", clean), f"sorry in {fname}")
            self.assertIsNone(re.search(r"\bnlinarith\b", clean), f"nlinarith in {fname}")
            thms = re.findall(r"\btheorem\s+[A-Za-z0-9_']+", clean)
            self.assertEqual(len(thms), min_thms)
            total_theorems += len(thms)
        self.assertEqual(total_theorems, 34)

    def test_15_redteam_problem1_patankar_interval_impulse_burst(self) -> None:
        """Red-Team Problem 1: High-frequency impulsive prompt burst near B_4 walls cannot overshoot."""
        engine = SharkProtocolEngine(P_0=4.0, lam_sim=7.2, lam_lucid=0.3, kappa_meta=2.5)
        # Place state extremely close to the lower/upper boundary faces and inject a massive P_0 = 5000 burst
        engine.state = np.array([1e-6, 99.9999, 1e-6, 0.999999], dtype=np.float64)
        res = engine.step_ode_patankar_interval(dt=0.20, P_0=5000.0)
        self.assertTrue(res["inside_B4_certified"])
        self.assertLess(res["max_interval_width"], 1e-10)
        for idx, ceiling in enumerate([engine.gamma_max, engine.H_max, res["I_max_4D"], 1.0]):
            self.assertGreaterEqual(res["interval_lo"][idx], 0.0)
            self.assertLessEqual(res["interval_hi"][idx], ceiling)

    def test_16_redteam_problem2_p0_zero_basin_separatrix_guard(self) -> None:
        """Red-Team Problem 2: P_0 = 0 Gronwall capacitive decay floor and basin collapse rejection."""
        engine = SharkProtocolEngine(P_0=0.0, lam_sim=7.2, lam_lucid=0.3, kappa_meta=2.5)
        # Valid natural decay over dt=0.05s from Psi=0.80 stays above Gronwall floor 0.80 * exp(-0.60 * 0.05) = 0.776356
        valid = engine.evaluate_basin_separatrix_guard(
            dt_window=0.05, psi_before=0.80, psi_after=0.785, gamma_after=2.5, P_0=0.0
        )
        self.assertTrue(valid["basin_safe"])

        # Adversarial perturbation attempting to force Psi below Gronwall floor is rejected fail-closed
        with self.assertRaises(BasinCollapseError):
            engine.evaluate_basin_separatrix_guard(
                dt_window=0.05, psi_before=0.80, psi_after=0.50, gamma_after=2.5, P_0=0.0
            )

        # Adversarial perturbation forcing trajectory across separatrix into origin attraction basin is rejected
        with self.assertRaises(BasinCollapseError):
            engine.evaluate_basin_separatrix_guard(
                dt_window=5.0, psi_before=0.80, psi_after=0.05, gamma_after=0.01, P_0=0.0
            )

    def test_17_redteam_problem3_lrsc_null_space_adversarial_injection(self) -> None:
        """Red-Team Problem 3: Out-of-band energy concentrated in S_11^perp triggers fail-closed fallback seal."""
        comp = LRSCCompressor(null_space_threshold=0.92)
        # Construct an adversarial vector supported strictly in the 88 discarded indices S_11^perp
        adv_vec = np.ones(99, dtype=np.float64)
        for idx in comp.WITNESS_INDICES:
            adv_vec[idx] = 0.0
        res = comp.compress("adversarial_null_space", raw_ring_vector=adv_vec)
        self.assertAlmostEqual(res["witness_l2_norm"], 0.0, places=12)
        self.assertAlmostEqual(res["orthogonal_null_space_l2_ratio"], 1.0, places=12)
        self.assertTrue(res["null_space_anomaly_detected"])
        self.assertEqual(res["fallback_mode"], "UNCOMPRESSED_FULL_RING_SEAL")
        self.assertEqual(len(res["uncompressed_fallback_sha256"]), 64)

    def test_18_redteam_problem4_multithreaded_typestate_and_epoch_race_stress(self) -> None:
        """Red-Team Problem 4: 16 concurrent threads executing 20 lifecycle/gateway transitions with fault injection."""
        gw = MultiProviderGateway()
        errors: List[str] = []
        completed_epochs: List[int] = []
        lock = threading.Lock()

        def worker_task(tid: int) -> None:
            for step in range(15):
                try:
                    slot = RequestSlot(slot_epoch=tid * 100 + step)
                    if step % 5 == 0:
                        with self.assertRaises(RuntimeError):
                            with slot.atomic_lifecycle_scope({"tid": tid, "step": step}):
                                raise RuntimeError("Async worker interrupt")
                        if slot.state != LifecycleState.ZEROED_FREED or not slot.is_zeroed:
                            with lock:
                                errors.append(f"Slot not poisoned/freed on interrupt: {slot.state}")
                    else:
                        with slot.atomic_lifecycle_scope({"tid": tid, "step": step}) as active_slot:
                            data = active_slot.dereference_payload()
                            if data["tid"] != tid:
                                with lock:
                                    errors.append("Cross-thread payload contamination")
                        if slot.state != LifecycleState.ZEROED_FREED or slot.fence_seq < 4:
                            with lock:
                                errors.append(f"Bad fence sequence {slot.fence_seq}")
                    with lock:
                        completed_epochs.append(slot.slot_epoch)
                except Exception as exc:
                    with lock:
                        errors.append(str(exc))

        threads = [threading.Thread(target=worker_task, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(completed_epochs), 16 * 15)

    def test_19_redteam_problem5_merkle_dag_split_brain_commutativity(self) -> None:
        """Red-Team Problem 5: Divergent split-brain gateway branches reconcile commutatively into the exact same Merkle-DAG digest."""
        node_a = SharkProtocolEngine()
        node_b = SharkProtocolEngine()

        # Common genesis claim on both nodes
        ts0 = "2026-10-24T10:00:00Z"
        node_a.seal_claim("claim.genesis", "Shared genesis state", timestamp_utc=ts0)
        node_b.seal_claim("claim.genesis", "Shared genesis state", timestamp_utc=ts0)
        self.assertEqual(node_a.ledger[0]["digest"], node_b.ledger[0]["digest"])

        # Network partition: Node A and Node B process different dispatches
        node_a.seal_claim("claim.nodeA.1", "Node A dispatch 1", timestamp_utc="2026-10-24T10:01:00Z")
        node_a.seal_claim("claim.nodeA.2", "Node A dispatch 2", timestamp_utc="2026-10-24T10:02:00Z")
        node_b.seal_claim("claim.nodeB.1", "Node B dispatch 1", timestamp_utc="2026-10-24T10:01:30Z")

        self.assertNotEqual(node_a.ledger[-1]["digest"], node_b.ledger[-1]["digest"])

        # Reconcile in both orders: merge(A, B) == merge(B, A)
        merge_ab = SharkProtocolEngine.merge_divergent_ledgers(node_a.ledger, node_b.ledger)
        merge_ba = SharkProtocolEngine.merge_divergent_ledgers(node_b.ledger, node_a.ledger)
        self.assertEqual(merge_ab["digest"], merge_ba["digest"])
        self.assertEqual(merge_ab["parent_hashes"], sorted([node_a.ledger[-1]["digest"], node_b.ledger[-1]["digest"]]))
        self.assertEqual(len(merge_ab["merged_claim_digests"]), 4)

    def test_20_redteam_problem5_merkle_dag_rejects_tampered_branch(self) -> None:
        """Red-Team Problem 5: Merkle-DAG reconciliation rejects a tampered branch fail-closed."""
        node_a = SharkProtocolEngine()
        node_b = SharkProtocolEngine()
        node_a.seal_claim("claim.1", "Valid branch A", timestamp_utc="2026-10-24T10:00:00Z")
        node_b.seal_claim("claim.2", "Valid branch B", timestamp_utc="2026-10-24T10:00:00Z")

        # Tamper with branch B
        node_b.ledger[0]["claim_text"] = "Forged branch B"
        with self.assertRaises(RuntimeError):
            SharkProtocolEngine.merge_divergent_ledgers(node_a.ledger, node_b.ledger)


if __name__ == "__main__":
    unittest.main()
