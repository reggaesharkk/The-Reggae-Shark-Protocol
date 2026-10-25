# The Reggae Shark Protocol (v1.1.2 -- Formal Verification & Red-Team Audited Edition)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23624605.svg)](https://doi.org/10.5281/zenodo.23624605)
[![License: MIT](https://img.shields.io/badge/Code_&_Lean_4-MIT-blue.svg)](LICENSE)
[![License: CC BY 4.0](https://img.shields.io/badge/Specification_PDF-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Lean 4](https://img.shields.io/badge/Lean_4-34_Theorems_(0_sorry)-brightgreen.svg)](lean/)

**Author:** Prince Upadhyay ([ORCID: 0009-0002-1170-4487](https://orcid.org/0009-0002-1170-4487) | `starxshark@gmail.com`)  
**Canonical Release DOI (`v1.1.2` / Zenodo v3):** [10.5281/zenodo.23624605](https://doi.org/10.5281/zenodo.23624605) *(Supersedes `v1.0.3` Deposit DOI: [10.5281/zenodo.23618033](https://doi.org/10.5281/zenodo.23618033))*  
**Licensing:** **MIT License** for all Python source code and Lean 4 formal proofs; **CC BY 4.0** for the technical specification manuscript (`paper/specification.tex` and `paper/specification.pdf`).  
**Epistemic Standard:** `Build. Attack. Falsify. Preserve.`

---

## Architectural Overview (Four Verification Layers)

**The Reggae Shark Protocol (`v1.1.2`)** is an application-layer verification kernel and multi-cloud AI execution gateway that binds every prompt dispatch to four deterministic mathematical and cryptographic checks:

| Layer | Module / Artifact | Enforced Mathematical & Cryptographic Invariant |
| :--- | :--- | :--- |
| **Layer 1** | [`shark_protocol/kernel.py`](shark_protocol/kernel.py) | **VRK v0.3.1 SHA-256 Hash Chain & Merkle-DAG Join (`intentseal-vrk-claim-v2`):** Commits every execution record to `prev_hash` and canonically sorted `parent_hashes` anchored at the frozen VRK trust root `f010a99d...05a0d0f` ([10.5281/zenodo.23018459](https://doi.org/10.5281/zenodo.23018459)), with commutative split-brain branch reconciliation (`merge_divergent_ledgers`). |
| **Layer 1B** | [`lean/TypestateLifecycle.lean`](lean/TypestateLifecycle.lean) | **Typestate Request-Lifecycle & Worker-Epoch Model (8 Theorems, `0 sorry`):** Formalizes a 6-state request automaton (`UNINIT -> PARTIAL_INIT -> SEALED_ACTIVE -> SHUTDOWN_CLEAN -> ZEROED_FREED` with `OOM_ABORT -> ABORTED_POISONED`) and monotonic `slot_epoch == worker_epoch` isolation that rules out partial-initialization dereferencing and cross-epoch worker-slot reads within the modelled state machine. |
| **Layer 2** | [`lean/ExistenceVerification.lean`](lean/ExistenceVerification.lean) & [`lean/BoundaryVerification.lean`](lean/BoundaryVerification.lean) | **4D Soft-Wall ODE Cognitive Dynamics Governor ($\mathcal{B}_4$):** Evolves $(\gamma, H_{	ext{obs}}, \dot{I}, \Psi)$ inside $\mathcal{B}_4 = [0, 10] 	imes [0, 100] 	imes [0, \dot{I}_{\max,	ext{4D}}] 	imes [0, 1]$ using adaptive sub-stepped RK4, an unconditionally box-invariant Patankar-Euler interval step (`step_ode_patankar_interval`), and a fail-closed Grönwall basin separatrix floor guard (`evaluate_basin_separatrix_guard`). |
| **Layer 3** | `LRSCCompressor` ([`shark_protocol/kernel.py`](shark_protocol/kernel.py)) | **Low-Rank Spectral Context Memory (`LRSC` $11/99 = 1/9$):** Projects prompt context onto the $M=99$ near-Nyquist cyclic ring basis, retains the certified $K=11$ witness subset $S_{11} = \{0,1,3,42..49\}$ ([10.17605/OSF.IO/NM5BW](https://doi.org/10.17605/OSF.IO/NM5BW) & [10.17605/OSF.IO/JAK5X](https://doi.org/10.17605/OSF.IO/JAK5X)), and monitors orthogonal complement ($S_{11}^\perp$) energy with an uncompressed SHA-256 fallback seal. |
| **Layer 4** | [`shark_protocol/gateway.py`](shark_protocol/gateway.py) | **Fail-Closed Multi-Cloud Gateway:** Rejects unknown providers (`GatewayConfigError`) and explicitly separates CI-verified offline execution (`VRK_OFFLINE_SEALED_SIMULATION`) from optional external cloud dispatch (`LIVE_API_DISPATCH`). |

---

## Canonical Lean 4 Provenance & Archive File Count (34 Zero-`sorry` Theorems)

This repository contains **24 tracked files in total: 23 SHA-256 hash-verified files plus [`MANIFEST_SHA256.txt`](MANIFEST_SHA256.txt)** (which cannot include its own hash). All three Lean 4 modules in [`lean/`](lean/) are compiled in CI via `lake build` with **zero `sorry` axioms and zero `nlinarith` heuristics**:

1. [`lean/ExistenceVerification.lean`](lean/ExistenceVerification.lean) (**17 theorems**, `SHA-256: eec9486803fb2e12f94c3ef966098acd31e4a66df8269ebe8cb59a937f7abcae`): Byte-for-byte identical to the canonical 8-face 4D box $\mathcal{B}_4$ module in *The Theory of Bounded Existence (`v1.0.0`)* ([10.5281/zenodo.23608244](https://doi.org/10.5281/zenodo.23608244)).
2. [`lean/BoundaryVerification.lean`](lean/BoundaryVerification.lean) (**9 theorems**, `SHA-256: 49229b6163b5a3a77dc83779a7dc5350502ff2b3d6a7f2de4d39996f4460e417`): Byte-for-byte identical to the canonical 6-face 3D soft-wall box $\mathcal{B}(e)$ module in *Physics v1.0 Appendix A (`v1.5`)* ([10.5281/zenodo.23534449](https://doi.org/10.5281/zenodo.23534449)).
3. [`lean/TypestateLifecycle.lean`](lean/TypestateLifecycle.lean) (**8 theorems**): Proves 5 request-lifecycle typestate and worker-epoch theorems (`oom_from_partial_init_is_poisoned`, `no_deref_after_partial_oom_abort`, `no_shutdown_uaf_on_poisoned_state`, `stale_epoch_read_rejected`, `typestate_and_epoch_security_certificate`) plus 3 red-team bridge theorems (`patankar_euler_step_in_box`, `psi_decay_floor_bound`, and `merkle_dag_merge_commutative`).

---

## Senior Red-Team Audit Board: Five Stress Resolutions

1. **Problem 1 (Continuous-to-Discrete Bridge Gap):** Explicit discrete solvers can overshoot a continuous Nagumo boundary if $\Delta t$ exceeds the local stiffness threshold. `SharkProtocolEngine.step_ode_patankar_interval()` closes this gap by combining an unconditionally box-invariant **Patankar-Euler fractional production-destruction update** with **2-ULP outward-rounded IEEE-754 interval enclosures** (`[interval_lo, interval_hi]`), backed by Lean 4 Theorem `patankar_euler_step_in_box` (`0 <= x_k <= x_max -> 0 <= x_{k+1} <= x_max` for all `dt > 0`).
2. **Problem 2 ($\mathcal{P}_0 = 0$ Basin Separatrix & Capacitive Floor):** Because $R_{	ext{self}}(x) \ge 0$ and $\Psi \in [0,1]$, Lean 4 Theorem `psi_decay_floor_bound` proves $d\Psi/dt \ge -\mu_\Psi \Psi$, giving the exact Grönwall capacitive lower bound $\Psi(t + \Delta t) \ge \Psi(t) e^{-\mu_\Psi \Delta t}$. Runtime guard `evaluate_basin_separatrix_guard()` enforces both this Grönwall floor and the cycle-persistence floor $\mathcal{P}_{	ext{eff}}(t) \ge \mathcal{P}_{	ext{eff}}^{	ext{floor}}$, raising `BasinCollapseError` fail-closed on adversarial collapse attempts.
3. **Problem 3 (LRSC $S_{11}^\perp$ Null-Space Adversarial Injection):** While the $10^{-3}$ LRSC threshold holds on the rank-41 odd-ring transfer subspace $\operatorname{Im}(V)$, an adversarial vector supported strictly in the 88 discarded indices $S_{11}^\perp$ has coordinate-sampling error $1.0$. `LRSCCompressor.compress()` computes the exact orthogonal energy ratio $\eta_\perp(x) = \|(I - P_{S_{11}})	ilde{x}\|_2 / \|	ilde{x}\|_2$ on every request; if $\eta_\perp(x) > 	au_{	ext{null}}$, it sets `null_space_anomaly_detected = True` and seals the full 99-mode `uncompressed_fallback_sha256` digest.
4. **Problem 4 (Concurrency & Thread-Synchronized Lifecycle Fences):** `RequestSlot` and `WorkerEpochGuard` synchronize every transition with a re-entrant mutex (`threading.RLock`), increment a monotonic atomic sequence counter `_fence_seq`, and provide `atomic_lifecycle_scope()` to poison and zero slots upon any mid-flight exception (verified across 16 concurrent worker threads in `test_18_multithreaded_typestate_and_epoch_race_stress`).
5. **Problem 5 (Distributed Split-Brain Merkle-DAG Reconciliation):** `SharkProtocolEngine.merge_divergent_ledgers()` validates divergent gateway branches back to the VRK trust root and emits a deterministic merge claim with canonically sorted `parent_hashes = sorted([tip_A, tip_B])` (proven commutative in Lean 4 Theorem `merkle_dag_merge_commutative`).

---

## What Is and Is Not Modelled (Epistemic Firewall)

- **Lifecycle Model Scope:** The theorems in `lean/TypestateLifecycle.lean` prove properties of the formal state-transition model, and `shark_protocol/kernel.py` enforces those invariants at the Python application layer. They are not a native C/PHP runtime patch, OS kernel memory protection mechanism, or hardware ARM64/x86 CPU cache-coherency protocol.
- **Gateway Verification Scope:** Only the deterministic offline verification path (`VRK_OFFLINE_SEALED_SIMULATION`) and local `127.0.0.1` loopback HTTP proxy are exercised and verified in CI. Live external cloud dispatch (`LIVE_API_DISPATCH` for Groq, Together AI, Google Gemini, and Hugging Face) is an optional runtime integration path requiring user API keys in `.env` and is not claimed as verified in CI.
- **Mathematical State Variable Scope:** $\Psi(t) \in [0,1]$ is strictly a bounded mathematical state variable of Eq. (B.4), not a claim of machine consciousness or sentience.

---

## Quickstart & Verification Commands

```bash
pip install -r requirements.txt
pip install -e .

# 1. Verify all 23 file hashes in MANIFEST_SHA256.txt:
sha256sum -c MANIFEST_SHA256.txt

# 2. Run the 20-test unit, integration & red-team stress suite:
pytest -v tests/

# 3. Run the CLI lifecycle & red-team self-audit:
shark-protocol --cli --audit-lifecycle

# 4. Launch the local loopback HTTP gateway server on http://127.0.0.1:8000:
shark-protocol --serve
```
