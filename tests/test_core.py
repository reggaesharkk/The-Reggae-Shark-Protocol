"""
Unit, Integration, Differential, and Adversarial Test Suite (`tests/test_core.py`)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Version: 1.3.2 (42 Tests: `test_01` .. `test_42`)

Covers:
  - Layer 1: VRK v0.3.1 SHA-256 hash-chain, Ed25519 signature, & tamper rejection (`test_01`, `test_02`, `test_05`)
  - Layer 1B: Typestate lifecycle, worker-epoch isolation, & unique reachability (`test_03`, `test_04`, `test_30`, `test_36`)
  - Layer 2: 4D soft-wall ODE integration, 8-face Nagumo bounds, `inside_B4_checked` (float64), & `inside_B4_mp_iv_certified` (200-bit `mpmath.iv`) (`test_06`, `test_07`, `test_15`, `test_16`, `test_21`, `test_31`, `test_33`)
  - Layer 3: LRSC 11/99 = 1/9 spectral projection, prompt commitment, & empirical attention sensitivity (`test_08`, `test_17`, `test_23`, `test_27`, `test_38`)
  - Layer 4: Multi-cloud gateway token registry (`sha256(token) -> tenant_id`), HTTP 401/413/429/503, per-tenant persistence, & socket timeout (`test_09`..`test_13`, `test_22`, `test_29`, `test_38`, `test_40`, `test_42`)
  - Lean 4: Zero-sorry, zero-axiom, `#print axioms`, & `#eval` transition-table diff across 42 theorems (`test_14`, `test_37`, `test_42`)
  - Cryptographic Provenance & Subprocess Isolation: `verify_exported_ledger`, `issued_at` head anti-replay, stateful `prev_hash == last_signed_digest` child signer, & child-only key file delivery (`test_18`..`test_20`, `test_24`..`test_26`, `test_28`, `test_32`, `test_34`, `test_35`, `test_39`, `test_41`)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import pathlib
import re
import tempfile
import threading
import unittest
from typing import Any, Dict, List
from unittest import mock
from urllib import request as urllib_request
from urllib.error import HTTPError

import numpy as np

import shark_protocol
from shark_protocol.gateway import (
    SOCKET_TIMEOUT_SECONDS,
    GatewayAuthError,
    GatewayCapacityError,
    GatewayConfigError,
    GatewayDispatchError,
    GatewayRateLimitError,
    MultiProviderGateway,
    create_gateway_http_server,
)
from shark_protocol.kernel import (
    FLOAT64_NORMAL_MIN,
    RELEASE_REFERENCE_HEAD_HASH,
    REVOKED_PUBLIC_PUBKEY_HEX,
    REVOKED_PUBLIC_SEED_SHA256,
    VRK_TRUST_ROOT_DIGEST,
    WP19_SEGMENTS_EXPECTED_SHA256,
    BasinCollapseError,
    Ed25519AuthoritySigner,
    IsolatedSignerSubprocess,
    LRSCCompressor,
    LifecycleEvent,
    LifecycleState,
    RequestSlot,
    SharkProtocolEngine,
    StaleWorkerEpochError,
    TypestateViolationError,
    WorkerEpochGuard,
    evaluate_wp19_piecewise_duhamel_study,
    sha256_canonical,
)


# Explicit, clearly-labelled untrusted test-only Ed25519 seed (never used in production)
UNTRUSTED_TEST_ONLY_SEED = b"UNTRUSTED_TEST_SEED_SHARK_V132!!"
UNTRUSTED_TEST_ONLY_SEED_HEX = UNTRUSTED_TEST_ONLY_SEED.hex()


class TestSharkProtocolSuite(unittest.TestCase):

    def setUp(self) -> None:
        self._prev_seed_env = os.environ.get("SHARK_ED25519_SEED_HEX")
        os.environ["SHARK_ED25519_SEED_HEX"] = UNTRUSTED_TEST_ONLY_SEED_HEX

    def tearDown(self) -> None:
        if self._prev_seed_env is None:
            os.environ.pop("SHARK_ED25519_SEED_HEX", None)
        else:
            os.environ["SHARK_ED25519_SEED_HEX"] = self._prev_seed_env

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
        self.assertTrue(res["ode_state"]["patankar_checked"])

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
                self.assertEqual(health["version"], shark_protocol.__version__)
                self.assertEqual(health["doi"], "10.5281/zenodo.23618032")

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
            try:
                self.assertEqual(ctx.exception.code, 400)
            finally:
                ctx.exception.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_14_lean4_42_theorems_zero_sorry_zero_axiom_and_canonical_hashes(self) -> None:
        root = pathlib.Path(__file__).resolve().parent.parent
        expected = {
            "BoundaryVerification.lean": (9, "49229b6163b5a3a77dc83779a7dc5350502ff2b3d6a7f2de4d39996f4460e417"),
            "ExistenceVerification.lean": (17, "eec9486803fb2e12f94c3ef966098acd31e4a66df8269ebe8cb59a937f7abcae"),
            "TypestateLifecycle.lean": (16, None),
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
                self.assertIn("sealed_active_unique_trace_from_uninit", thms)
                for t_name in thms:
                    self.assertIn(f"#print axioms {t_name}", clean, f"Missing #print axioms for {t_name}")
            total_theorems += len(thms)
        self.assertEqual(total_theorems, 42)

    def test_15_patankar_interval_impulse_burst_checked(self) -> None:
        engine = SharkProtocolEngine(P_0=4.0, lam_sim=7.2, lam_lucid=0.3, kappa_meta=2.5)
        engine.state = np.array([1e-6, 99.9999, 1e-6, 0.999999], dtype=np.float64)
        res = engine.step_ode_patankar_interval(dt=0.20, P_0=5000.0)
        self.assertTrue(res["inside_B4_checked"])
        self.assertNotIn("inside_B4_certified", res)
        self.assertLess(res["max_interval_width"], 1e-10)
        for idx, ceiling in enumerate([engine.gamma_max, engine.H_max, res["I_max_4D"], 1.0]):
            self.assertGreaterEqual(res["interval_lo"][idx], 0.0)
            self.assertLessEqual(res["interval_hi"][idx], ceiling)

    def test_16_p0_zero_basin_separatrix_guard(self) -> None:
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

    def test_17_lrsc_null_space_adversarial_injection(self) -> None:
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

    def test_18_multithreaded_typestate_and_epoch_race_stress(self) -> None:
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

    def test_19_merkle_dag_split_brain_commutativity(self) -> None:
        node_a = SharkProtocolEngine()
        node_b = SharkProtocolEngine()

        ts0 = "2026-10-26T10:00:00Z"
        node_a.seal_claim("claim.genesis", "Shared genesis state", timestamp_utc=ts0)
        node_b.seal_claim("claim.genesis", "Shared genesis state", timestamp_utc=ts0)
        self.assertEqual(node_a.ledger[0]["digest"], node_b.ledger[0]["digest"])

        node_a.seal_claim("claim.nodeA.1", "Node A dispatch 1", timestamp_utc="2026-10-26T10:01:00Z")
        node_a.seal_claim("claim.nodeA.2", "Node A dispatch 2", timestamp_utc="2026-10-26T10:02:00Z")
        node_b.seal_claim("claim.nodeB.1", "Node B dispatch 1", timestamp_utc="2026-10-26T10:01:30Z")

        self.assertNotEqual(node_a.ledger[-1]["digest"], node_b.ledger[-1]["digest"])

        merge_ab = SharkProtocolEngine.merge_divergent_ledgers(node_a.ledger, node_b.ledger)
        merge_ba = SharkProtocolEngine.merge_divergent_ledgers(node_b.ledger, node_a.ledger)
        self.assertEqual(merge_ab["digest"], merge_ba["digest"])
        self.assertEqual(merge_ab["parent_hashes"], sorted([node_a.ledger[-1]["digest"], node_b.ledger[-1]["digest"]]))
        self.assertEqual(len(merge_ab["merged_claim_digests"]), 4)

    def test_20_merkle_dag_rejects_tampered_branch(self) -> None:
        node_a = SharkProtocolEngine()
        node_b = SharkProtocolEngine()
        node_a.seal_claim("claim.1", "Valid branch A", timestamp_utc="2026-10-26T10:00:00Z")
        node_b.seal_claim("claim.2", "Valid branch B", timestamp_utc="2026-10-26T10:00:00Z")

        node_b.ledger[0]["claim_text"] = "Forged branch B"
        with self.assertRaises(RuntimeError):
            SharkProtocolEngine.merge_divergent_ledgers(node_a.ledger, node_b.ledger)

    def test_21_ieee754_subnormal_and_ftz_positivity_floor(self) -> None:
        engine = SharkProtocolEngine(P_0=0.0, lam_sim=0.0, lam_lucid=0.0, kappa_meta=2.5)
        engine.state = np.array([1e-320, 1e-320, 1e-320, 1e-320], dtype=np.float64)
        res = engine.step_ode_patankar_interval(dt=0.05, P_0=0.0)
        self.assertTrue(res["inside_B4_checked"])
        for lo_val in res["interval_lo"]:
            self.assertGreaterEqual(lo_val, FLOAT64_NORMAL_MIN)
            self.assertGreater(lo_val, 0.0)

        engine.state = np.array([0.0, 0.0, 0.0, 0.0], dtype=np.float64)
        res_ftz = engine.step_ode_patankar_interval(dt=0.05, P_0=1.0)
        self.assertTrue(res_ftz["inside_B4_checked"])
        for lo_val in res_ftz["interval_lo"]:
            self.assertGreaterEqual(lo_val, FLOAT64_NORMAL_MIN)

    def test_22_multitenant_isolation_and_waking_drive_floor(self) -> None:
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

    def test_23_subthreshold_lrsc_bandlimited_witness_and_perturbation_bound(self) -> None:
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

    def test_24_freethreaded_lock_encapsulation_and_snapshot_consistency(self) -> None:
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

    def test_25_merkle_dag_nway_associativity_and_idempotence(self) -> None:
        node_a = SharkProtocolEngine()
        node_b = SharkProtocolEngine()
        node_c = SharkProtocolEngine()

        ts_gen = "2026-10-26T12:00:00Z"
        for node in (node_a, node_b, node_c):
            node.seal_claim("claim.genesis", "Common root", timestamp_utc=ts_gen)

        node_a.seal_claim("claim.A", "Partition A work", timestamp_utc="2026-10-26T12:01:00Z")
        node_b.seal_claim("claim.B", "Partition B work", timestamp_utc="2026-10-26T12:02:00Z")
        node_c.seal_claim("claim.C", "Partition C work", timestamp_utc="2026-10-26T12:03:00Z")

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

    def test_26_multi_parent_tail_forgery_rejected(self) -> None:
        """Forging a tail entry with 2 arbitrary parent hashes + recomputed digest/sig is rejected."""
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

        ok, msg = SharkProtocolEngine.verify_chain_list(engine.ledger + [forged], expected_pubkey=engine.public_key_hex)
        self.assertFalse(ok)
        self.assertIn("forgery rejected", msg)

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

        ok_fm, msg_fm = SharkProtocolEngine.verify_chain_list(engine.ledger + [forged_merge], expected_pubkey=engine.public_key_hex)
        self.assertFalse(ok_fm)
        self.assertIn("unknown or unverified merge parent", msg_fm)

    def test_27_prompt_and_response_commitment_collision_resistance(self) -> None:
        """'a', 'b', 'Z', 'aaaa', and 'zzzz' produce distinct LRSC digests and sealed prompt/response hashes."""
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

    def test_28_ed25519_whole_chain_rewrite_and_ondisk_evidence_gate(self) -> None:
        """Rewriting the entire chain & recomputing all SHA-256 digests without the private key fails Ed25519 verification."""
        engine = SharkProtocolEngine(signing_seed=b"\x11" * 32)
        engine.seal_claim("claim.1", "Authentic record 1")
        engine.seal_claim("claim.2", "Authentic record 2")
        self.assertTrue(engine.verify_ledger_integrity()[0])

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

    def test_29_gateway_fail_closed_gemini_header_capacity_and_http_hardening(self) -> None:
        """Live provider failure raises GatewayDispatchError; Gemini uses x-goog-api-key; capacity cap raises GatewayCapacityError; HTTP enforces 413/401."""
        gw = MultiProviderGateway(max_tenants=4)

        # 1. Verify hard tenant capacity cap at max_tenants=4 (default + 3 additional tenants; 5th raises GatewayCapacityError without evicting)
        for i in range(3):
            gw.get_tenant_engine(f"tenant_{i}")
        self.assertEqual(len(gw._tenant_engines), 4)
        with self.assertRaises(GatewayCapacityError):
            gw.get_tenant_engine("tenant_overflow")
        self.assertIn("default", gw._tenant_engines)
        self.assertIn("tenant_0", gw._tenant_engines)

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
            req_unauth = urllib_request.Request(f"http://127.0.0.1:{port}/health", method="GET")
            with self.assertRaises(HTTPError) as ctx401:
                urllib_request.urlopen(req_unauth, timeout=5)
            try:
                self.assertEqual(ctx401.exception.code, 401)
            finally:
                ctx401.exception.close()

            big_body = json.dumps({"prompt": "X" * 300, "provider": "groq"}).encode("utf-8")
            req_413 = urllib_request.Request(
                f"http://127.0.0.1:{port}/v1/execute",
                data=big_body,
                headers={"Content-Type": "application/json", "Authorization": "Bearer top_secret_token"},
                method="POST",
            )
            with self.assertRaises(HTTPError) as ctx413:
                urllib_request.urlopen(req_413, timeout=5)
            try:
                self.assertEqual(ctx413.exception.code, 413)
            finally:
                ctx413.exception.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_30_zeroed_freed_strictly_terminal_absorbing(self) -> None:
        """Once a RequestSlot reaches ZEROED_FREED, any further event raises TypestateViolationError without leaving ZEROED_FREED."""
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

    def test_31_mpmath_iv_200bit_patankar_interval_enclosure(self) -> None:
        """200-bit outward-rounded mpmath.iv Patankar-Euler enclosure & INTERVAL_CERTIFIED_RESULT VRK seal."""
        engine = SharkProtocolEngine(P_0=4.0, lam_sim=7.2, lam_lucid=0.3, kappa_meta=2.5)
        bundle = engine.seal_interval_certified_patankar_claim(dt=0.05, P_0=4.0, dps=60)
        cert = bundle["certificate"]
        vrk = bundle["vrk_entry"]

        self.assertTrue(cert["inside_B4_mp_iv_certified"])
        self.assertLess(cert["max_mp_iv_width"], 1e-45)
        self.assertLess(cert["float64_to_mp_iv_max_drift"], 1e-12)
        self.assertEqual(vrk["claim_class"], "INTERVAL_CERTIFIED_RESULT")
        ok, msg = engine.verify_ledger_integrity()
        self.assertTrue(ok, msg)

    def test_32_isolated_signer_subprocess_key_isolation(self) -> None:
        """IsolatedSignerSubprocess holds Ed25519 seed in a separate OS PID; parent holds no seed and EXPORT_SECRET_KEY is rejected."""
        custom_seed = b"\x42" * 32
        direct_signer = Ed25519AuthoritySigner(seed=custom_seed)
        with IsolatedSignerSubprocess(seed=custom_seed) as iso_signer:
            self.assertNotEqual(iso_signer.pid, os.getpid())
            self.assertIsNone(iso_signer._seed)
            self.assertEqual(iso_signer.public_key_hex, direct_signer.public_key_hex)

            for attr_val in vars(iso_signer).values():
                self.assertNotEqual(attr_val, custom_seed)
                self.assertNotEqual(attr_val, custom_seed.hex())

            test_digest = hashlib.sha256(b"subprocess_isolation_test").hexdigest()
            sig_iso = iso_signer.sign_digest_hex(test_digest, prev_hash=VRK_TRUST_ROOT_DIGEST)
            self.assertEqual(sig_iso, direct_signer.sign_digest_hex(test_digest))
            self.assertTrue(
                Ed25519AuthoritySigner.verify_digest_signature(iso_signer.public_key_hex, test_digest, sig_iso)
            )

            bad_resp = iso_signer.send_raw_command("EXPORT_SECRET_KEY")
            self.assertFalse(bad_resp["ok"])
            self.assertIn("Forbidden IPC command", bad_resp["error"])

    def test_33_wp19_piecewise_duhamel_120_segment_parameter_study(self) -> None:
        """120-segment piecewise Duhamel parameter study vs. whole-path Gronwall blowup & VRK seal."""
        engine = SharkProtocolEngine()
        bundle = engine.seal_wp19_duhamel_interval_claim(local_dissipative_rate="-3.50")
        cert = bundle["certificate"]
        vrk = bundle["vrk_entry"]

        self.assertEqual(cert["n_segments"], 120)
        self.assertTrue(cert["duhamel_remainder_below_c500_bound"])
        self.assertTrue(cert["preserved_whole_path_exceeds_c500_bound"])
        self.assertLess(cert["piecewise_duhamel_interval_hi"], 1.0)
        self.assertGreater(cert["suppression_factor_lo"], 1e10)
        self.assertGreater(cert["critical_segment_growth_rate_mu_crit"], 20.0)
        self.assertEqual(cert["continuum_all_cutoff_status"], "OPEN")
        self.assertEqual(vrk["claim_class"], "NUMERICAL_OBSERVATION")
        self.assertEqual(cert["epistemic_status"], "ILLUSTRATIVE_PARAMETER_STUDY_GIVEN_ASSUMED_RATES")
        self.assertEqual(cert["data_file_sha256"], WP19_SEGMENTS_EXPECTED_SHA256)
        ok, msg = engine.verify_ledger_integrity()
        self.assertTrue(ok, msg)

    def test_34_cli_full_lifecycle_and_verification_selftest(self) -> None:
        """Verify run_lifecycle_and_redteam_audit passes all formal, interval, and cryptographic gates."""
        engine = SharkProtocolEngine()
        report = engine.run_lifecycle_and_redteam_audit()
        self.assertTrue(report["patankar_interval_step_checked"])
        self.assertTrue(report["mpmath_iv_200bit_certified"])
        self.assertTrue(report["isolated_signer_subprocess_verified"])
        self.assertTrue(report["wp19_parameter_study_evaluated"])
        self.assertTrue(report["all_checks_passed"])

    def test_35_mandatory_seed_pinned_verifier_signed_head_and_fsync(self) -> None:
        """Refuses startup without seed; requires keyword-only expected_pubkey; rejects random/revoked-seed forgeries & tail truncation."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        os.environ.pop("SHARK_ED25519_SEED_HEX", None)
        with self.assertRaises(RuntimeError):
            Ed25519AuthoritySigner()
        with self.assertRaises(RuntimeError):
            IsolatedSignerSubprocess(generate_ephemeral=False)
        with self.assertRaises(RuntimeError):
            SharkProtocolEngine()

        with IsolatedSignerSubprocess(generate_ephemeral=True) as eph_signer:
            self.assertIsNone(eph_signer._seed)
            self.assertEqual(len(eph_signer.public_key_hex), 64)
            d_test = hashlib.sha256(b"ephemeral_child_key").hexdigest()
            sig_eph = eph_signer.sign_digest_hex(d_test, prev_hash=VRK_TRUST_ROOT_DIGEST)
            self.assertTrue(Ed25519AuthoritySigner.verify_digest_signature(eph_signer.public_key_hex, d_test, sig_eph))

        os.environ["SHARK_ED25519_SEED_HEX"] = UNTRUSTED_TEST_ONLY_SEED_HEX

        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_file = pathlib.Path(tmpdir) / "ledger.jsonl"
            engine = SharkProtocolEngine(ledger_path=ledger_file)
            engine.seal_claim("claim.1", "First entry")
            engine.seal_claim("claim.2", "Second entry")
            self.assertTrue(ledger_file.exists())
            disk_lines = [json.loads(line) for line in ledger_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(disk_lines), 2)

            with self.assertRaises(TypeError):
                SharkProtocolEngine.verify_chain_list(engine.ledger)  # type: ignore[call-arg]

            attacker_signer = Ed25519AuthoritySigner(seed=b"\x77" * 32)
            forged_rand = dict(engine.ledger[-1])
            forged_rand.pop("digest", None)
            forged_rand.pop("ed25519_signature", None)
            forged_rand["index"] = 3
            forged_rand["prev_hash"] = engine.ledger[-1]["digest"]
            forged_rand["parent_hashes"] = [engine.ledger[-1]["digest"]]
            forged_rand["signer_pubkey"] = attacker_signer.public_key_hex
            d_rand = sha256_canonical(forged_rand)
            forged_rand["digest"] = d_rand
            forged_rand["ed25519_signature"] = attacker_signer.sign_digest_hex(d_rand)

            ok_r, msg_r = SharkProtocolEngine.verify_chain_list(
                engine.ledger + [forged_rand], expected_pubkey=engine.public_key_hex
            )
            self.assertFalse(ok_r)
            self.assertIn("signer_pubkey mismatch", msg_r)

            revoked_seed = hashlib.sha256(
                b"shark_protocol_v1_2_0_default_ed25519_seed:" + VRK_TRUST_ROOT_DIGEST.encode("ascii")
            ).digest()
            self.assertEqual(hashlib.sha256(revoked_seed).hexdigest(), REVOKED_PUBLIC_SEED_SHA256)
            with self.assertRaises(ValueError):
                Ed25519AuthoritySigner(seed=revoked_seed)

            raw_ret_priv = Ed25519PrivateKey.from_private_bytes(revoked_seed)
            ret_pub_hex = raw_ret_priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ).hex()
            self.assertEqual(ret_pub_hex, REVOKED_PUBLIC_PUBKEY_HEX)
            forged_ret = dict(forged_rand)
            forged_ret.pop("digest", None)
            forged_ret.pop("ed25519_signature", None)
            forged_ret["signer_pubkey"] = ret_pub_hex
            d_ret = sha256_canonical(forged_ret)
            forged_ret["digest"] = d_ret
            forged_ret["ed25519_signature"] = raw_ret_priv.sign(d_ret.encode("ascii")).hex()

            ok_ret1, _ = SharkProtocolEngine.verify_chain_list(
                engine.ledger + [forged_ret], expected_pubkey=engine.public_key_hex
            )
            self.assertFalse(ok_ret1)
            ok_ret2, msg_ret2 = SharkProtocolEngine.verify_chain_list(
                [forged_ret], expected_pubkey=REVOKED_PUBLIC_PUBKEY_HEX
            )
            self.assertFalse(ok_ret2)
            self.assertIn("revoked", msg_ret2)

            head_rec = engine.sign_head_record()
            ok_head, msg_head = SharkProtocolEngine.verify_chain_list(
                engine.ledger, expected_pubkey=engine.public_key_hex, signed_head=head_rec
            )
            self.assertTrue(ok_head, msg_head)

            ok_trunc, msg_trunc = SharkProtocolEngine.verify_chain_list(
                engine.ledger[:-1], expected_pubkey=engine.public_key_hex, signed_head=head_rec
            )
            self.assertFalse(ok_trunc)
            self.assertIn("truncation", msg_trunc)

    def test_36_differential_lean_transition_table_vs_python_request_slot(self) -> None:
        """Differential test comparing 200 random event traces across RequestSlot and data/lean_transition_table.json."""
        import random

        root = pathlib.Path(__file__).resolve().parent.parent
        table_path = root / "data/lean_transition_table.json"
        self.assertTrue(table_path.exists())
        lean_table = json.loads(table_path.read_text(encoding="utf-8"))

        self.assertIsNone(RequestSlot.is_zeroed.fset)

        all_states = list(LifecycleState)
        all_events = list(LifecycleEvent)

        for st in all_states:
            for ev in all_events:
                slot = RequestSlot(slot_epoch=1, state=st)
                next_py = slot.step_total_automaton(ev)
                next_lean = LifecycleState(lean_table[st.value][ev.value])
                self.assertEqual(next_py, next_lean, f"Mismatch on ({st}, {ev})")
                self.assertEqual(slot.is_zeroed, (next_py == LifecycleState.ZEROED_FREED))

        rng = random.Random(20261026)
        for trace_idx in range(200):
            init_st = rng.choice(all_states)
            trace_len = rng.randint(1, 25)
            events = [rng.choice(all_events) for _ in range(trace_len)]
            slot = RequestSlot(slot_epoch=trace_idx + 1, state=init_st)
            cur_lean = init_st.value
            for ev in events:
                cur_py = slot.step_total_automaton(ev).value
                cur_lean = lean_table[cur_lean][ev.value]
                self.assertEqual(cur_py, cur_lean)
                self.assertEqual(slot.is_zeroed, (cur_py == "ZEROED_FREED"))

    def test_37_axioms_check_all_42_theorems_and_output_parser(self) -> None:
        """Verify lean/AxiomsCheck.lean covers all 42 theorems and tools/check_lean_axioms.py rejects sorryAx or custom axioms."""
        import sys
        root = pathlib.Path(__file__).resolve().parent.parent
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from tools.check_lean_axioms import (
            discover_declared_theorems,
            verify_axioms_check_source,
            verify_lean_axioms_output,
        )

        expected_42 = verify_axioms_check_source(root)
        self.assertEqual(len(expected_42), 42)
        decl_map = discover_declared_theorems(root)
        self.assertIn("perturbation_budget_scaling", decl_map["lean/TypestateLifecycle.lean"])
        self.assertIn("projection_independent_of_secret", decl_map["lean/TypestateLifecycle.lean"])
        self.assertIn("sealed_active_unique_trace_from_uninit", decl_map["lean/TypestateLifecycle.lean"])

        valid_lines = [
            f"'{thm}' depends on axioms: [propext, Classical.choice, Quot.sound]"
            for thm in expected_42
        ]
        parsed = verify_lean_axioms_output("\n".join(valid_lines), root)
        self.assertEqual(len(parsed), 42)

        with self.assertRaises(AssertionError):
            verify_lean_axioms_output("\n".join(valid_lines[:-1]), root)
        with self.assertRaises(AssertionError):
            verify_lean_axioms_output(valid_lines[0].replace("propext", "sorryAx") + "\n" + "\n".join(valid_lines[1:]), root)
        with self.assertRaises(AssertionError):
            verify_lean_axioms_output(valid_lines[0].replace("propext", "customUnverifiedAxiom") + "\n" + "\n".join(valid_lines[1:]), root)

    def test_38_empirical_attention_perturbation_and_per_tenant_rate_limit(self) -> None:
        """Empirical attention perturbation vs budget and per-tenant sliding-window rate limiting."""
        rng = np.random.default_rng(20261026)
        x_raw = rng.normal(0.0, 1.0, size=99)
        x_unit = x_raw / max(float(np.linalg.norm(x_raw)), 1e-12)
        noise = rng.normal(0.0, 0.005, size=x_unit.shape)
        x_pert = x_unit + noise
        delta_norm = float(np.linalg.norm(x_pert - x_unit))

        X1 = x_unit.reshape(9, 11)
        X2 = x_pert.reshape(9, 11)
        W_Q = rng.normal(0.0, 0.35, size=(11, 8))
        W_K = rng.normal(0.0, 0.35, size=(11, 8))
        W_V = rng.normal(0.0, 0.35, size=(11, 8))

        def softmax_attn(X: np.ndarray) -> np.ndarray:
            Q = X @ W_Q
            K = X @ W_K
            V = X @ W_V
            scores = (Q @ K.T) / np.sqrt(8.0)
            scores = scores - np.max(scores, axis=-1, keepdims=True)
            weights = np.exp(scores)
            weights = weights / np.sum(weights, axis=-1, keepdims=True)
            return weights @ V

        out1 = softmax_attn(X1)
        out2 = softmax_attn(X2)
        emp_diff = float(np.linalg.norm(out2 - out1))
        L_local = 4.0 * float(np.linalg.norm(W_Q, 2) * np.linalg.norm(W_K, 2) * np.linalg.norm(W_V, 2) + np.linalg.norm(W_V, 2))
        budget = L_local * delta_norm
        self.assertLessEqual(emp_diff, budget)

        gw = MultiProviderGateway(rate_limit_per_window=2, rate_limit_window_sec=60.0)
        tok_tenant = gw.derive_tenant_from_token("secret_bearer_token_abc")
        self.assertTrue(tok_tenant.startswith("t_"))
        gw.process_request("Req 1", provider="groq", tenant_id=tok_tenant)
        gw.process_request("Req 2", provider="groq", tenant_id=tok_tenant)
        with self.assertRaises(GatewayRateLimitError):
            gw.process_request("Req 3 exceeding rate limit", provider="groq", tenant_id=tok_tenant)

    def test_39_signed_head_issued_at_and_verify_exported_ledger_anti_replay(self) -> None:
        """Signed heads include issued_at; verify_exported_ledger requires signed_head & min_length, blocking truncation and stale-head replay."""
        engine = SharkProtocolEngine()
        engine.seal_claim("claim.1", "Step 1", timestamp_utc="2026-10-26T08:00:00Z")
        engine.seal_claim("claim.2", "Step 2", timestamp_utc="2026-10-26T08:01:00Z")
        old_head_2 = engine.sign_head_record(issued_at="2026-10-26T08:02:00Z")
        self.assertEqual(old_head_2["schema"], "intentseal-vrk-head-v2")
        self.assertEqual(old_head_2["issued_at"], "2026-10-26T08:02:00Z")

        engine.seal_claim("claim.3", "Step 3", timestamp_utc="2026-10-26T08:03:00Z")
        engine.seal_claim("claim.4", "Step 4", timestamp_utc="2026-10-26T08:04:00Z")
        latest_head_4 = engine.sign_head_record(issued_at="2026-10-26T08:05:00Z")

        # 1. Valid exported 4-entry ledger with latest_head_4 and min_length=4 passes
        ok, msg = SharkProtocolEngine.verify_exported_ledger(
            engine.ledger,
            signed_head=latest_head_4,
            expected_pubkey=engine.public_key_hex,
            min_length=4,
            min_issued_at="2026-10-26T08:04:00Z",
            expected_head_hash=latest_head_4["head_hash"],
        )
        self.assertTrue(ok, msg)

        # 2. Omitting signed_head is rejected
        ok_no_head, msg_no_head = SharkProtocolEngine.verify_exported_ledger(
            engine.ledger[:2],
            signed_head={},  # empty / missing head
            expected_pubkey=engine.public_key_hex,
            min_length=1,
        )
        self.assertFalse(ok_no_head)
        self.assertIn("requires a non-empty signed_head", msg_no_head)

        # 3. Attacker truncates ledger to 2 entries and attaches the older valid head of length 2:
        #    rejected both by min_length=4 and by min_issued_at="2026-10-26T08:04:00Z"
        ok_replay_len, msg_replay_len = SharkProtocolEngine.verify_exported_ledger(
            engine.ledger[:2],
            signed_head=old_head_2,
            expected_pubkey=engine.public_key_hex,
            min_length=4,
        )
        self.assertFalse(ok_replay_len)
        self.assertIn("min_length", msg_replay_len)

        ok_replay_ts, msg_replay_ts = SharkProtocolEngine.verify_exported_ledger(
            engine.ledger[:2],
            signed_head=old_head_2,
            expected_pubkey=engine.public_key_hex,
            min_length=2,
            min_issued_at="2026-10-26T08:04:00Z",
        )
        self.assertFalse(ok_replay_ts)
        self.assertIn("precedes min_issued_at", msg_replay_ts)

        # 4. Verify published reference release head in data/release_head.json
        root = pathlib.Path(__file__).resolve().parent.parent
        ref_head_file = root / "data/release_head.json"
        self.assertTrue(ref_head_file.exists())
        ref_bundle = json.loads(ref_head_file.read_text(encoding="utf-8"))
        self.assertEqual(ref_bundle["signed_head"]["head_hash"], RELEASE_REFERENCE_HEAD_HASH)
        ok_ref, msg_ref = SharkProtocolEngine.verify_exported_ledger(
            ref_bundle["ledger"],
            signed_head=ref_bundle["signed_head"],
            expected_pubkey=ref_bundle["expected_pubkey"],
            min_length=len(ref_bundle["ledger"]),
            expected_head_hash=RELEASE_REFERENCE_HEAD_HASH,
        )
        self.assertTrue(ok_ref, msg_ref)

    def test_40_gateway_token_registry_401_per_tenant_persistence_and_503_capacity(self) -> None:
        """Token registry maps sha256(token) -> tenant_id, rejects unknown tokens with 401, persists per-tenant ledgers, and returns 503 at cap."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gw = MultiProviderGateway(max_tenants=2, ledger_dir=tmpdir)
            gw.register_tenant_token("token_alice_secret", "tenant_alice")
            gw.register_tenant_token("token_bob_secret", "tenant_bob")

            server, _ = create_gateway_http_server(host="127.0.0.1", port=0, gateway=gw)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                # 1. Unknown Bearer token is rejected with HTTP 401
                req_bad = urllib_request.Request(
                    f"http://127.0.0.1:{port}/v1/execute",
                    data=json.dumps({"prompt": "Hello", "provider": "groq"}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": "Bearer unknown_attacker_token"},
                    method="POST",
                )
                with self.assertRaises(HTTPError) as ctx401:
                    urllib_request.urlopen(req_bad, timeout=5)
                try:
                    self.assertEqual(ctx401.exception.code, 401)
                finally:
                    ctx401.exception.close()

                # 2. Alice's token executes under tenant_alice and persists to tenant_alice.jsonl
                req_alice = urllib_request.Request(
                    f"http://127.0.0.1:{port}/v1/execute",
                    data=json.dumps({"prompt": "Alice request", "provider": "groq"}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": "Bearer token_alice_secret"},
                    method="POST",
                )
                with urllib_request.urlopen(req_alice, timeout=5) as resp_a:
                    out_a = json.loads(resp_a.read().decode("utf-8"))
                    self.assertEqual(out_a["tenant_id"], "tenant_alice")

                alice_ledger_file = pathlib.Path(tmpdir) / "tenant_alice.jsonl"
                self.assertTrue(alice_ledger_file.exists())

                # 3. Attempting to impersonate tenant_bob using Alice's token is rejected with HTTP 401
                req_spoof = urllib_request.Request(
                    f"http://127.0.0.1:{port}/v1/execute",
                    data=json.dumps({"prompt": "Spoof", "provider": "groq", "tenant_id": "tenant_bob"}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": "Bearer token_alice_secret"},
                    method="POST",
                )
                with self.assertRaises(HTTPError) as ctx_spoof:
                    urllib_request.urlopen(req_spoof, timeout=5)
                try:
                    self.assertEqual(ctx_spoof.exception.code, 401)
                finally:
                    ctx_spoof.exception.close()

                # 4. At max_tenants=2 ('default' + 'tenant_alice'), Bob's token returns HTTP 503 without evicting Alice
                req_bob = urllib_request.Request(
                    f"http://127.0.0.1:{port}/v1/execute",
                    data=json.dumps({"prompt": "Bob at cap", "provider": "groq"}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": "Bearer token_bob_secret"},
                    method="POST",
                )
                with self.assertRaises(HTTPError) as ctx503:
                    urllib_request.urlopen(req_bob, timeout=5)
                try:
                    self.assertEqual(ctx503.exception.code, 503)
                finally:
                    ctx503.exception.close()

                self.assertEqual(len(gw.get_tenant_engine("tenant_alice").ledger), 1)
            finally:
                server.shutdown()
                server.server_close()

            # 5. Re-instantiating gateway from the same ledger_dir reloads tenant_alice's persisted ledger
            gw_reloaded = MultiProviderGateway(max_tenants=4, ledger_dir=tmpdir)
            self.assertEqual(len(gw_reloaded.get_tenant_engine("tenant_alice").ledger), 1)

    def test_41_isolated_signer_subprocess_prev_hash_chain_and_keyfile_delivery(self) -> None:
        """Child signer loads key from seed_file without parent env exposure and enforces prev_hash == last_signed_digest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = pathlib.Path(tmpdir) / "authority.key"
            secret_bytes = b"\x5a" * 32
            key_file.write_bytes(secret_bytes)
            os.chmod(key_file, 0o600)

            # Remove SHARK_ED25519_SEED_HEX from parent environment completely
            os.environ.pop("SHARK_ED25519_SEED_HEX", None)
            self.assertNotIn("SHARK_ED25519_SEED_HEX", os.environ)

            with IsolatedSignerSubprocess(seed_file=key_file) as child_signer:
                self.assertIsNone(child_signer._seed)
                self.assertNotIn("SHARK_ED25519_SEED_HEX", os.environ)
                engine = SharkProtocolEngine(signer=child_signer)

                c1 = engine.seal_claim("claim.1", "First chained entry", timestamp_utc="2026-10-26T09:00:00Z")
                c2 = engine.seal_claim("claim.2", "Second chained entry", timestamp_utc="2026-10-26T09:01:00Z")
                self.assertEqual(child_signer.last_signed_digest, c2["digest"])
                self.assertEqual(child_signer.signed_count, 2)

                # Attempting to sign an out-of-chain / forked entry with prev_hash != c2["digest"] is rejected by child
                forged_digest = hashlib.sha256(b"forked_history_attempt").hexdigest()
                with self.assertRaises(ValueError) as ctx_fork:
                    child_signer.sign_digest_hex(forged_digest, prev_hash=VRK_TRUST_ROOT_DIGEST)
                self.assertIn("Chain continuity violation", str(ctx_fork.exception))

                # Attempting to sign a truncated head (len=1 or head_hash=c1["digest"]) is rejected by child
                with self.assertRaises(ValueError) as ctx_head:
                    child_signer.sign_head_digest_hex(forged_digest, head_hash=c1["digest"], ledger_length=1)
                self.assertIn("Head commitment mismatch", str(ctx_head.exception))

                # Signing the legitimate tip head succeeds and verifies
                head_rec = engine.sign_head_record(issued_at="2026-10-26T09:02:00Z")
                ok, msg = SharkProtocolEngine.verify_exported_ledger(
                    engine.ledger,
                    signed_head=head_rec,
                    expected_pubkey=engine.public_key_hex,
                    min_length=2,
                )
                self.assertTrue(ok, msg)

            os.environ["SHARK_ED25519_SEED_HEX"] = UNTRUSTED_TEST_ONLY_SEED_HEX

    def test_42_packaging_single_source_of_truth_lean_eval_diff_and_socket_timeout(self) -> None:
        """Verify no setup.py, synchronized pyproject.toml & requirements.txt, version consistency, Lean #eval diff gate, and socket timeout."""
        import sys
        root = pathlib.Path(__file__).resolve().parent.parent
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from tools.check_lean_axioms import verify_lean_transition_table_eval

        # 1. setup.py is removed; pyproject.toml and requirements.txt list identical dependencies
        self.assertFalse((root / "setup.py").exists())
        req_lines = [
            line.strip()
            for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        pyproject_txt = (root / "pyproject.toml").read_text(encoding="utf-8")
        import tomllib
        py_deps = tomllib.loads(pyproject_txt)["project"]["dependencies"]
        self.assertEqual(req_lines, py_deps)
        self.assertNotIn("sympy", pyproject_txt)

        # 2. Version 1.3.2 is consistent across __init__.py, pyproject.toml, CITATION.cff, README.md, SECURITY.md, and specification.tex
        ver = shark_protocol.__version__
        self.assertEqual(ver, "1.3.2")
        self.assertIn(f'version = "{ver}"', pyproject_txt)
        self.assertIn(f'version: "{ver}"', (root / "CITATION.cff").read_text(encoding="utf-8"))
        self.assertIn(ver, (root / "README.md").read_text(encoding="utf-8"))
        self.assertIn(ver, (root / "SECURITY.md").read_text(encoding="utf-8"))
        self.assertIn(ver, (root / "paper/specification.tex").read_text(encoding="utf-8"))

        # 3. Lean #eval transition-table diff verifier accepts exact JSON and rejects any drift
        committed_json_str = (root / "data/lean_transition_table.json").read_text(encoding="utf-8")
        compact_str = json.dumps(json.loads(committed_json_str), separators=(",", ":"))
        simulated_lean_eval_stdout = json.dumps(compact_str) + "\n"
        parsed = verify_lean_transition_table_eval(simulated_lean_eval_stdout, root)
        self.assertEqual(len(parsed), 6)

        drifted_obj = json.loads(committed_json_str)
        drifted_obj["UNINIT"]["BEGIN_INIT"] = "ABORTED_POISONED"
        drifted_stdout = json.dumps(json.dumps(drifted_obj)) + "\n"
        with self.assertRaises(AssertionError):
            verify_lean_transition_table_eval(drifted_stdout, root)

        # 4. Gateway HTTP handler enforces socket timeout
        server, _ = create_gateway_http_server(host="127.0.0.1", port=0)
        try:
            self.assertEqual(server.RequestHandlerClass.timeout, SOCKET_TIMEOUT_SECONDS)
            self.assertEqual(SOCKET_TIMEOUT_SECONDS, 10.0)
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
