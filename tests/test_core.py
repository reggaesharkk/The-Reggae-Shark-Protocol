"""
Unit, Integration, and Red-Team Stress Suite (`tests/test_core.py`)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Version: 1.2.0 (30 Tests: `test_01` .. `test_30`)

Covers:
  - Layer 1: VRK v0.3.1 SHA-256 hash-chain, Ed25519 signature, & tamper rejection (`test_01`, `test_02`, `test_05`)
  - Layer 1B: Typestate lifecycle & worker-epoch isolation (`test_03`, `test_04`)
  - Layer 2: 4D soft-wall ODE integration & 8-face Nagumo bounds (`test_06`, `test_07`)
  - Layer 3: LRSC 11/99 = 1/9 spectral projection (`test_08`)
  - Layer 4: Multi-cloud gateway config, offline simulation, & loopback HTTP server (`test_09`..`test_13`)
  - Lean 4: Zero-sorry, zero-axiom, `#print axioms`, & canonical SHA-256 audit across 38 theorems (`test_14`)
  - Problem 1..5 & Probe A..E stress tests (`test_15`..`test_25`)
  - Audit Item 1 Fix: Multi-parent tail ledger forgery rejection (`test_26`)
  - Audit Item 2 Fix: Prompt/response commitment & single-char/constant-byte collision resistance (`test_27`)
  - Audit Item 3 Fix: Ed25519 whole-chain rewrite rejection & on-disk evidence anchor gate (`test_28`)
  - Audit Item 4 Fix: Fail-closed live provider dispatch, Gemini header, bounded tenant LRU, & HTTP 413/auth/500 hardening (`test_29`)
  - Audit Item 5 Fix: `ZEROED_FREED` terminal absorbing state in Python & Lean 4 trace model (`test_30`)
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import threading
import unittest
from typing import Any, Dict, List
from unittest import mock
from urllib import request as urllib_request
from urllib.error import HTTPError

import numpy as np

from shark_protocol.gateway import (
    GatewayConfigError,
    GatewayDispatchError,
    MultiProviderGateway,
    create_gateway_http_server,
)
from shark_protocol.kernel import (
    FLOAT64_NORMAL_MIN,
    VRK_TRUST_ROOT_DIGEST,
    BasinCollapseError,
    Ed25519AuthoritySigner,
    LRSCCompressor,
    LifecycleEvent,
    LifecycleState,
    RequestSlot,
    SharkProtocolEngine,
    StaleWorkerEpochError,
    TypestateViolationError,
    WorkerEpochGuard,
    sha256_canonical,
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

        slot_req2 = guard.begin_request()
        slot_req2.transition(LifecycleEvent.SEAL_SUCCESS, payload={"token": "req2_public"})
        with self.assertRaises(StaleWorkerEpochError):
            guard.read_slot(slot_req1)

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
                self.assertEqual(health["version"], "1.2.0")
                self.assertEqual(health["doi"], "10.5281/zenodo.23635351")

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

    def test_14_lean4_38_theorems_zero_sorry_zero_axiom_and_canonical_hashes(self) -> None:
        root = pathlib.Path(__file__).resolve().parent.parent
        expected = {
            "BoundaryVerification.lean": (9, "49229b6163b5a3a77dc83779a7dc5350502ff2b3d6a7f2de4d39996f4460e417"),
            "ExistenceVerification.lean": (17, "eec9486803fb2e12f94c3ef966098acd31e4a66df8269ebe8cb59a937f7abcae"),
            "TypestateLifecycle.lean": (12, None),
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
            self.assertIsNone(re.search(r"\baxiom\b", clean), f"custom axiom in {fname}")
            self.assertIsNone(re.search(r"\bnlinarith\b", clean), f"nlinarith in {fname}")
            thms = re.findall(r"\btheorem\s+([A-Za-z0-9_']+)", clean)
            self.assertEqual(len(thms), min_thms)
            if fname == "TypestateLifecycle.lean":
                for t_name in thms:
                    self.assertIn(f"#print axioms {t_name}", clean, f"Missing #print axioms for {t_name}")
            total_theorems += len(thms)
        self.assertEqual(total_theorems, 38)

    def test_15_redteam_problem1_patankar_interval_impulse_burst(self) -> None:
        engine = SharkProtocolEngine(P_0=4.0, lam_sim=7.2, lam_lucid=0.3, kappa_meta=2.5)
        engine.state = np.array([1e-6, 99.9999, 1e-6, 0.999999], dtype=np.float64)
        res = engine.step_ode_patankar_interval(dt=0.20, P_0=5000.0)
        self.assertTrue(res["inside_B4_certified"])
        self.assertLess(res["max_interval_width"], 1e-10)
        for idx, ceiling in enumerate([engine.gamma_max, engine.H_max, res["I_max_4D"], 1.0]):
            self.assertGreaterEqual(res["interval_lo"][idx], 0.0)
            self.assertLessEqual(res["interval_hi"][idx], ceiling)

    def test_16_redteam_problem2_p0_zero_basin_separatrix_guard(self) -> None:
        engine = SharkProtocolEngine(P_0=0.0, lam_sim=7.2, lam_lucid=0.3, kappa_meta=2.5)
        valid = engine.evaluate_basin_separatrix_guard(
            dt_window=0.05, psi_before=0.80, psi_after=0.785, gamma_after=2.5, P_0=0.0
        )
        self.assertTrue(valid["basin_safe"])

        with self.assertRaises(BasinCollapseError):
            engine.evaluate_basin_separatrix_guard(
                dt_window=0.05, psi_before=0.80, psi_after=0.50, gamma_after=2.5, P_0=0.0
            )

        with self.assertRaises(BasinCollapseError):
            engine.evaluate_basin_separatrix_guard(
                dt_window=5.0, psi_before=0.80, psi_after=0.05, gamma_after=0.01, P_0=0.0
            )

    def test_17_redteam_problem3_lrsc_null_space_adversarial_injection(self) -> None:
        comp = LRSCCompressor(null_space_threshold=0.92)
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
        node_a = SharkProtocolEngine()
        node_b = SharkProtocolEngine()

        ts0 = "2026-10-25T10:00:00Z"
        node_a.seal_claim("claim.genesis", "Shared genesis state", timestamp_utc=ts0)
        node_b.seal_claim("claim.genesis", "Shared genesis state", timestamp_utc=ts0)
        self.assertEqual(node_a.ledger[0]["digest"], node_b.ledger[0]["digest"])

        node_a.seal_claim("claim.nodeA.1", "Node A dispatch 1", timestamp_utc="2026-10-25T10:01:00Z")
        node_a.seal_claim("claim.nodeA.2", "Node A dispatch 2", timestamp_utc="2026-10-25T10:02:00Z")
        node_b.seal_claim("claim.nodeB.1", "Node B dispatch 1", timestamp_utc="2026-10-25T10:01:30Z")

        self.assertNotEqual(node_a.ledger[-1]["digest"], node_b.ledger[-1]["digest"])

        merge_ab = SharkProtocolEngine.merge_divergent_ledgers(node_a.ledger, node_b.ledger)
        merge_ba = SharkProtocolEngine.merge_divergent_ledgers(node_b.ledger, node_a.ledger)
        self.assertEqual(merge_ab["digest"], merge_ba["digest"])
        self.assertEqual(merge_ab["parent_hashes"], sorted([node_a.ledger[-1]["digest"], node_b.ledger[-1]["digest"]]))
        self.assertEqual(len(merge_ab["merged_claim_digests"]), 4)

    def test_20_redteam_problem5_merkle_dag_rejects_tampered_branch(self) -> None:
        node_a = SharkProtocolEngine()
        node_b = SharkProtocolEngine()
        node_a.seal_claim("claim.1", "Valid branch A", timestamp_utc="2026-10-25T10:00:00Z")
        node_b.seal_claim("claim.2", "Valid branch B", timestamp_utc="2026-10-25T10:00:00Z")

        node_b.ledger[0]["claim_text"] = "Forged branch B"
        with self.assertRaises(RuntimeError):
            SharkProtocolEngine.merge_divergent_ledgers(node_a.ledger, node_b.ledger)

    def test_21_deep_probe_a_ieee754_subnormal_and_ftz_positivity_floor(self) -> None:
        engine = SharkProtocolEngine(P_0=0.0, lam_sim=0.0, lam_lucid=0.0, kappa_meta=2.5)
        engine.state = np.array([1e-320, 1e-320, 1e-320, 1e-320], dtype=np.float64)
        res = engine.step_ode_patankar_interval(dt=0.05, P_0=0.0)
        self.assertTrue(res["inside_B4_certified"])
        for lo_val in res["interval_lo"]:
            self.assertGreaterEqual(lo_val, FLOAT64_NORMAL_MIN)
            self.assertGreater(lo_val, 0.0)

        engine.state = np.array([0.0, 0.0, 0.0, 0.0], dtype=np.float64)
        res_ftz = engine.step_ode_patankar_interval(dt=0.05, P_0=1.0)
        self.assertTrue(res_ftz["inside_B4_certified"])
        for lo_val in res_ftz["interval_lo"]:
            self.assertGreaterEqual(lo_val, FLOAT64_NORMAL_MIN)

    def test_22_deep_probe_b_multitenant_isolation_and_waking_drive_floor(self) -> None:
        gw = MultiProviderGateway(min_waking_p0=1.0)
        for _ in range(30):
            att_res = gw.process_request(
                prompt="",
                provider="groq",
                tenant_id="attacker_tenant",
                requested_p0=0.0,
            )
            self.assertEqual(att_res["status"], "SEALED_OK")
            self.assertGreaterEqual(att_res["effective_p0"], 1.0)
            self.assertTrue(att_res["separatrix_guard"]["basin_safe"])

        legit_res = gw.process_request(
            prompt="Legitimate research query",
            provider="groq",
            tenant_id="legitimate_scientist",
        )
        self.assertEqual(legit_res["status"], "SEALED_OK")
        self.assertEqual(legit_res["worker_epoch"], 2)
        self.assertEqual(len(gw.get_tenant_engine("legitimate_scientist").ledger), 1)
        self.assertEqual(len(gw.get_tenant_engine("attacker_tenant").ledger), 30)

    def test_23_deep_probe_c_subthreshold_lrsc_bandlimited_witness_and_lipschitz_bound(self) -> None:
        comp = LRSCCompressor(null_space_threshold=0.92, attn_weight_norm=1.0, attn_head_dim=64)
        self.assertGreater(comp.channel_witness_sigma_min, 0.18)

        vec = np.zeros(99, dtype=np.float64)
        vec[0] = 0.43588989 / comp.envelope[0]
        vec[2] = 0.90000000 / comp.envelope[2]
        res = comp.compress("sub_threshold_probe", raw_ring_vector=vec)

        self.assertFalse(res["null_space_anomaly_detected"])
        self.assertLessEqual(res["orthogonal_null_space_l2_ratio"], 0.92)
        self.assertLessEqual(
            res["attention_perturbation_upper_bound"],
            res["attention_perturbation_threshold_ceiling"],
        )
        self.assertEqual(len(res["bandlimited_witness_vector"]), 11)
        self.assertEqual(len(res["lrsc_sha256"]), 64)
        self.assertEqual(len(res["uncompressed_fallback_sha256"]), 64)

        gw = MultiProviderGateway()
        gw_out = gw.process_request("Dual seal verification", provider="groq")
        self.assertEqual(gw_out["vrk_seal"]["lrsc_sha256"], gw_out["lrsc"]["lrsc_sha256"])
        self.assertEqual(
            gw_out["vrk_seal"]["uncompressed_ring_sha256"],
            gw_out["lrsc"]["uncompressed_fallback_sha256"],
        )

    def test_24_deep_probe_d_freethreaded_lock_encapsulation_and_snapshot_consistency(self) -> None:
        guard = WorkerEpochGuard(initial_epoch=1)
        slot = guard.begin_request()
        slot.transition(LifecycleEvent.SEAL_SUCCESS, payload={"k": "v"})
        errors: List[str] = []

        def reader_loop() -> None:
            for _ in range(50):
                try:
                    ep, st, zeroed, fseq = slot.snapshot()
                    if zeroed and st not in (LifecycleState.ZEROED_FREED, LifecycleState.ABORTED_POISONED):
                        errors.append(f"Torn state/zeroed read: state={st}, zeroed={zeroed}")
                    if fseq < 2:
                        errors.append(f"Non-monotonic fence_seq={fseq}")
                except Exception as exc:
                    errors.append(str(exc))

        threads = [threading.Thread(target=reader_loop) for _ in range(12)]
        for t in threads:
            t.start()
        guard.finish_request(slot, abort=False)
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(slot.state, LifecycleState.ZEROED_FREED)
        self.assertTrue(slot.is_zeroed)

    def test_25_deep_probe_e_merkle_dag_nway_associativity_and_idempotence(self) -> None:
        node_a = SharkProtocolEngine()
        node_b = SharkProtocolEngine()
        node_c = SharkProtocolEngine()

        ts_gen = "2026-10-25T12:00:00Z"
        for node in (node_a, node_b, node_c):
            node.seal_claim("claim.genesis", "Common root", timestamp_utc=ts_gen)

        node_a.seal_claim("claim.A", "Partition A work", timestamp_utc="2026-10-25T12:01:00Z")
        node_b.seal_claim("claim.B", "Partition B work", timestamp_utc="2026-10-25T12:02:00Z")
        node_c.seal_claim("claim.C", "Partition C work", timestamp_utc="2026-10-25T12:03:00Z")

        merge_ab = SharkProtocolEngine.merge_divergent_ledgers(node_a.ledger, node_b.ledger)
        merge_ab_c = SharkProtocolEngine.merge_divergent_ledgers([merge_ab], node_c.ledger)

        merge_bc = SharkProtocolEngine.merge_divergent_ledgers(node_b.ledger, node_c.ledger)
        merge_a_bc = SharkProtocolEngine.merge_divergent_ledgers(node_a.ledger, [merge_bc])

        merge_ca = SharkProtocolEngine.merge_divergent_ledgers(node_c.ledger, node_a.ledger)
        merge_ca_b = SharkProtocolEngine.merge_divergent_ledgers([merge_ca], node_b.ledger)
        merge_abc_direct = SharkProtocolEngine.merge_divergent_ledgers(
            node_a.ledger, node_b.ledger, node_c.ledger
        )

        self.assertEqual(merge_ab_c["digest"], merge_a_bc["digest"])
        self.assertEqual(merge_ab_c["digest"], merge_ca_b["digest"])
        self.assertEqual(merge_ab_c["digest"], merge_abc_direct["digest"])
        self.assertEqual(len(merge_ab_c["leaf_frontier_tips"]), 3)
        self.assertEqual(len(merge_ab_c["merged_claim_digests"]), 4)

        merge_ab_b = SharkProtocolEngine.merge_divergent_ledgers([merge_ab], node_b.ledger)
        self.assertEqual(merge_ab_b["digest"], merge_ab["digest"])

    def test_26_audit_item1_multi_parent_tail_forgery_rejected(self) -> None:
        """Audit Item 1: Forging a tail entry with 2 arbitrary parent hashes + recomputed digest/sig is rejected."""
        engine = SharkProtocolEngine()
        engine.seal_claim("claim.legit", "Legitimate entry")

        fake_p1 = "1" * 64
        fake_p2 = "2" * 64
        forged = dict(engine.ledger[-1])
        forged.pop("digest", None)
        forged.pop("ed25519_signature", None)
        forged["index"] = 2
        forged["parent_hashes"] = [fake_p1, fake_p2]
        forged["prev_hash"] = fake_p1
        forged_digest = sha256_canonical(forged)
        forged["digest"] = forged_digest
        forged["ed25519_signature"] = engine.signer.sign_digest_hex(forged_digest)

        ok, msg = SharkProtocolEngine.verify_chain_list(engine.ledger + [forged])
        self.assertFalse(ok)
        self.assertIn("forgery rejected", msg)

        # Also test forging a merge entry with fake parent_hashes not in merged_branch_records
        forged_merge = dict(forged)
        forged_merge.pop("digest", None)
        forged_merge.pop("ed25519_signature", None)
        forged_merge["leaf_frontier_tips"] = [fake_p1, fake_p2]
        forged_merge["merged_claim_digests"] = [engine.ledger[0]["digest"]]
        forged_merge["merged_claim_ids"] = ["claim.legit"]
        forged_merge["merged_branch_records"] = [engine.ledger[0]]
        fm_digest = sha256_canonical(forged_merge)
        forged_merge["digest"] = fm_digest
        forged_merge["ed25519_signature"] = engine.signer.sign_digest_hex(fm_digest)

        ok_fm, msg_fm = SharkProtocolEngine.verify_chain_list(engine.ledger + [forged_merge])
        self.assertFalse(ok_fm)
        self.assertIn("unknown or unverified merge parent", msg_fm)

    def test_27_audit_item2_prompt_and_response_commitment_collision_resistance(self) -> None:
        """Audit Item 2: 'a', 'b', 'Z', 'aaaa', and 'zzzz' produce distinct LRSC digests and sealed prompt/response hashes."""
        comp = LRSCCompressor()
        prompts = ["a", "b", "Z", "aaaa", "zzzz"]
        lrsc_hashes = set()
        uncomp_hashes = set()
        witness_vecs = set()

        for p in prompts:
            out = comp.compress(p)
            lrsc_hashes.add(out["lrsc_sha256"])
            uncomp_hashes.add(out["uncompressed_fallback_sha256"])
            witness_vecs.add(tuple(out["witness_vector"]))
            self.assertEqual(out["prompt_sha256"], hashlib.sha256(p.encode("utf-8")).hexdigest())

        self.assertEqual(len(lrsc_hashes), len(prompts))
        self.assertEqual(len(uncomp_hashes), len(prompts))
        self.assertEqual(len(witness_vecs), len(prompts))

        gw = MultiProviderGateway()
        r_a = gw.process_request("a", provider="groq")
        r_b = gw.process_request("b", provider="groq")
        self.assertNotEqual(r_a["vrk_seal"]["prompt_sha256"], r_b["vrk_seal"]["prompt_sha256"])
        self.assertNotEqual(r_a["vrk_seal"]["response_sha256"], r_b["vrk_seal"]["response_sha256"])
        self.assertNotEqual(r_a["vrk_seal"]["lrsc_sha256"], r_b["vrk_seal"]["lrsc_sha256"])

    def test_28_audit_item3_ed25519_whole_chain_rewrite_and_ondisk_evidence_gate(self) -> None:
        """Audit Item 3: Rewriting the entire chain & recomputing all SHA-256 digests without the private key fails Ed25519 verification."""
        engine = SharkProtocolEngine(signing_seed=b"\x11" * 32)
        engine.seal_claim("claim.1", "Authentic record 1")
        engine.seal_claim("claim.2", "Authentic record 2")
        self.assertTrue(engine.verify_ledger_integrity()[0])

        # Attacker rewrites the entire ledger and recomputes all prev_hash and digest fields
        rewritten: List[Dict[str, Any]] = []
        for idx, orig in enumerate(engine.ledger):
            forged = {k: v for k, v in orig.items() if k not in ("digest", "ed25519_signature")}
            forged["claim_text"] = f"Attacker rewritten record {idx}"
            prev = VRK_TRUST_ROOT_DIGEST if idx == 0 else rewritten[idx - 1]["digest"]
            forged["prev_hash"] = prev
            forged["parent_hashes"] = [prev]
            forged["digest"] = sha256_canonical(forged)
            forged["ed25519_signature"] = orig["ed25519_signature"]
            rewritten.append(forged)

        ok, msg = SharkProtocolEngine.verify_chain_list(rewritten, expected_pubkey=engine.public_key_hex)
        self.assertFalse(ok)
        self.assertIn("Ed25519 signature verification failed", msg)

        # Even if attacker signs with their own rogue Ed25519 key, expected_pubkey check rejects it
        rogue_signer = Ed25519AuthoritySigner(seed=b"\x99" * 32)
        for item in rewritten:
            body = {k: v for k, v in item.items() if k not in ("digest", "ed25519_signature")}
            body["signer_pubkey"] = rogue_signer.public_key_hex
            item["signer_pubkey"] = rogue_signer.public_key_hex
            item["digest"] = sha256_canonical(body)
            item["ed25519_signature"] = rogue_signer.sign_digest_hex(item["digest"])
        ok_rogue, msg_rogue = SharkProtocolEngine.verify_chain_list(rewritten, expected_pubkey=engine.public_key_hex)
        self.assertFalse(ok_rogue)
        self.assertIn("signer_pubkey mismatch", msg_rogue)

        # On-disk evidence gate rejects non-existent file or non-existent #anchor
        with self.assertRaises(ValueError):
            engine.seal_claim(
                "bad.anchor",
                "Non-existent symbol anchor",
                claim_class="REPRODUCED_RESULT",
                evidence=[
                    {"role": "definition", "path": "lean/ExistenceVerification.lean#NonExistentSymbol123"},
                    {"role": "execution_record", "path": "shark_protocol/kernel.py#step_ode"},
                    {"role": "independent_replication", "path": "shark_protocol/kernel.py#step_ode_patankar_interval"},
                ],
            )

    def test_29_audit_item4_gateway_fail_closed_gemini_header_lru_and_http_hardening(self) -> None:
        """Audit Item 4: Live provider failure raises GatewayDispatchError; Gemini uses x-goog-api-key; LRU bounds tenants; HTTP enforces 413/auth."""
        gw = MultiProviderGateway(max_tenants=4)

        # 1. Verify bounded tenant LRU eviction at max_tenants=4
        for i in range(10):
            gw.get_tenant_engine(f"tenant_{i}")
        self.assertLessEqual(len(gw._tenant_engines), 4)
        self.assertIn("default", gw._tenant_engines)

        # 2. Verify Gemini passes API key in x-goog-api-key header, NOT in URL
        captured_calls: List[Dict[str, Any]] = []

        class DummyResp:
            def raise_for_status(self) -> None:
                return
            def json(self) -> Dict[str, Any]:
                return {"candidates": [{"content": {"parts": [{"text": "gemini_ok"}]}}]}

        def fake_post(url: str, headers: Dict[str, str], json: Dict[str, Any], timeout: int) -> DummyResp:
            captured_calls.append({"url": url, "headers": headers})
            return DummyResp()

        with mock.patch("shark_protocol.gateway.requests.post", side_effect=fake_post):
            out_txt = gw._dispatch_external_provider("gemini", "hello", "SECRET_GEMINI_KEY")
            self.assertEqual(out_txt, "gemini_ok")
            self.assertNotIn("SECRET_GEMINI_KEY", captured_calls[0]["url"])
            self.assertEqual(captured_calls[0]["headers"].get("x-goog-api-key"), "SECRET_GEMINI_KEY")

        # 3. Verify that when a live API key is configured and the provider call fails, process_request raises GatewayDispatchError fail-closed
        with mock.patch.dict(os.environ, {"GROQ_API_KEY": "gsk_live_test_key"}):
            with mock.patch("shark_protocol.gateway.requests.post", side_effect=RuntimeError("Upstream 503")):
                with self.assertRaises(GatewayDispatchError):
                    gw.process_request("Must fail closed", provider="groq")

        # 4. Verify non-loopback 0.0.0.0 bind is rejected without allow_remote + auth_token
        with self.assertRaises(GatewayConfigError):
            create_gateway_http_server(host="0.0.0.0", port=0)

        # 5. Verify HTTP 413 Payload Too Large and 401 Bearer Token Auth
        server, _ = create_gateway_http_server(
            host="127.0.0.1", port=0, auth_token="top_secret_token", max_content_length=128
        )
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # Unauthenticated request -> 401
            req_unauth = urllib_request.Request(f"http://127.0.0.1:{port}/health", method="GET")
            with self.assertRaises(HTTPError) as ctx401:
                urllib_request.urlopen(req_unauth, timeout=5)
            self.assertEqual(ctx401.exception.code, 401)

            # Oversized payload (> 128 bytes) -> 413
            big_body = json.dumps({"prompt": "X" * 300, "provider": "groq"}).encode("utf-8")
            req_413 = urllib_request.Request(
                f"http://127.0.0.1:{port}/v1/execute",
                data=big_body,
                headers={"Content-Type": "application/json", "Authorization": "Bearer top_secret_token"},
                method="POST",
            )
            with self.assertRaises(HTTPError) as ctx413:
                urllib_request.urlopen(req_413, timeout=5)
            self.assertEqual(ctx413.exception.code, 413)
        finally:
            server.shutdown()
            server.server_close()

    def test_30_audit_item5_zeroed_freed_strictly_terminal_absorbing(self) -> None:
        """Audit Item 5: Once a RequestSlot reaches ZEROED_FREED, any further event raises TypestateViolationError without leaving ZEROED_FREED."""
        slot = RequestSlot(slot_epoch=1)
        slot.transition(LifecycleEvent.BEGIN_INIT)
        slot.transition(LifecycleEvent.SEAL_SUCCESS, payload={"a": 1})
        slot.run_clean_destructor()
        slot.transition(LifecycleEvent.ZERO_AND_FREE)
        self.assertEqual(slot.state, LifecycleState.ZEROED_FREED)

        for ev in LifecycleEvent:
            with self.assertRaises(TypestateViolationError):
                slot.transition(ev)
            self.assertEqual(slot.state, LifecycleState.ZEROED_FREED)
            self.assertTrue(slot.is_zeroed)


if __name__ == "__main__":
    unittest.main()
