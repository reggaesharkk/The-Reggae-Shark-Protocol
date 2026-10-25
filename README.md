# The Reggae Shark Protocol (v1.2.0 -- Double-PhD Red-Team Certified Final Edition)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23624605.svg)](https://doi.org/10.5281/zenodo.23624605)
[![License: MIT](https://img.shields.io/badge/Code_&_Lean_4-MIT-blue.svg)](LICENSE)
[![License: CC BY 4.0](https://img.shields.io/badge/Specification_PDF-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Lean 4](https://img.shields.io/badge/Lean_4-38_Theorems_(0_sorry)-brightgreen.svg)](lean/)
[![Tests](https://img.shields.io/badge/Pytest-25%2F25_Passing-brightgreen.svg)](tests/test_core.py)

**Author:** Prince Upadhyay ([ORCID: 0009-0002-1170-4487](https://orcid.org/0009-0002-1170-4487) | `starxshark@gmail.com`)  
**Release Version:** `v1.2.0` (Zenodo `v4` Final Edition | Supersedes `v3` DOI: [10.5281/zenodo.23624605](https://doi.org/10.5281/zenodo.23624605), `v2` DOI: [10.5281/zenodo.23620074](https://doi.org/10.5281/zenodo.23620074), and `v1.0.3` DOI: [10.5281/zenodo.23618033](https://doi.org/10.5281/zenodo.23618033))  
**Licensing:** **MIT License** for all Python source code and Lean 4 formal proofs; **CC BY 4.0** for the technical specification manuscript (`paper/specification.tex` and `paper/specification.pdf`).  
**Epistemic Standard:** `Build. Attack. Falsify. Preserve.`

---

## Architectural Overview (Four Verification Layers)

**The Reggae Shark Protocol (`v1.2.0`)** is an application-layer verification kernel and multi-cloud AI execution gateway that binds every prompt dispatch to four deterministic mathematical and cryptographic checks:

| Layer | Module / Artifact | Enforced Mathematical & Cryptographic Invariant |
| :--- | :--- | :--- |
| **Layer 1** | [`shark_protocol/kernel.py`](shark_protocol/kernel.py) | **VRK v0.3.1 SHA-256 Hash Chain & $N$-Way Associative Merkle-DAG Join (`intentseal-vrk-claim-v2`):** Commits every execution record to `prev_hash`, `lrsc_sha256`, and `uncompressed_ring_sha256` anchored at the frozen VRK trust root `f010a99d...05a0d0f` ([10.5281/zenodo.23018459](https://doi.org/10.5281/zenodo.23018459)), with commutative, associative, and idempotent split-brain reconciliation (`merge_divergent_ledgers`). |
| **Layer 1B** | [`lean/TypestateLifecycle.lean`](lean/TypestateLifecycle.lean) | **Typestate Request-Lifecycle, Worker-Epoch & PEP 703 Lock Isolation (12 Theorems, `0 sorry`):** Formalizes a 6-state request automaton (`UNINIT -> PARTIAL_INIT -> SEALED_ACTIVE -> SHUTDOWN_CLEAN -> ZEROED_FREED` with `OOM_ABORT -> ABORTED_POISONED`), monotonic `slot_epoch == worker_epoch` isolation, and mutex-encapsulated `snapshot()` reads safe for free-threaded Python (`--disable-gil`). |
| **Layer 2** | [`lean/ExistenceVerification.lean`](lean/ExistenceVerification.lean) & [`lean/BoundaryVerification.lean`](lean/BoundaryVerification.lean) | **4D Soft-Wall ODE Cognitive Dynamics Governor ($\mathcal{B}_4$, 26 Theorems, `0 sorry`):** Evolves $(\gamma, H_{	ext{obs}}, \dot{I}, \Psi)$ inside $\mathcal{B}_4 = [0, 10] 	imes [0, 100] 	imes [0, \dot{I}_{\max,	ext{4D}}] 	imes [0, 1]$ using adaptive sub-stepped RK4, a subnormal-safe Patankar-Euler interval integrator (`step_ode_patankar_interval` with normal float64 floor $2.225 	imes 10^{-308}$), and a fail-closed Grönwall basin separatrix floor guard (`evaluate_basin_separatrix_guard`). |
| **Layer 3** | `LRSCCompressor` ([`shark_protocol/kernel.py`](shark_protocol/kernel.py)) | **Bandlimited Low-Rank Spectral Context Memory (`LRSC` $11/99 = 1/9$):** Projects prompt context onto the $M=99$ odd-ring channel filter $V_{	ext{ring}}$ ($\sigma_{\min}(S_{11}) = 0.18164624 > 0$, [10.17605/OSF.IO/NM5BW](https://doi.org/10.17605/OSF.IO/NM5BW) & [10.17605/OSF.IO/JAK5X](https://doi.org/10.17605/OSF.IO/JAK5X)), computes the downstream attention Lipschitz error bound, and binds both compressed and uncompressed SHA-256 digests. |
| **Layer 4** | [`shark_protocol/gateway.py`](shark_protocol/gateway.py) | **Fail-Closed Multi-Tenant Gateway:** Isolates per-tenant ODE/ledger instances (`get_tenant_engine`), enforces waking basal sensory drive $\mathcal{P}_0 \ge 1.0 \gg 10/99$, rejects unknown providers (`GatewayConfigError`), and separates CI-verified offline execution (`VRK_OFFLINE_SEALED_SIMULATION`) from optional external cloud dispatch (`LIVE_API_DISPATCH`). |

---

## Canonical Lean 4 Provenance & Archive File Count (38 Zero-`sorry` Theorems)

This repository contains **24 tracked files in total: 23 SHA-256 hash-verified files plus [`MANIFEST_SHA256.txt`](MANIFEST_SHA256.txt)** (which cannot include its own hash). All three Lean 4 modules in [`lean/`](lean/) are compiled in CI via `lake build` with **zero `sorry` axioms and zero `nlinarith` heuristics**:

1. [`lean/ExistenceVerification.lean`](lean/ExistenceVerification.lean) (**17 theorems**, `SHA-256: eec9486803fb2e12f94c3ef966098acd31e4a66df8269ebe8cb59a937f7abcae`): Byte-for-byte identical to the canonical 8-face 4D box $\mathcal{B}_4$ module in *The Theory of Bounded Existence (`v1.0.0`)* ([10.5281/zenodo.23608244](https://doi.org/10.5281/zenodo.23608244)).
2. [`lean/BoundaryVerification.lean`](lean/BoundaryVerification.lean) (**9 theorems**, `SHA-256: 49229b6163b5a3a77dc83779a7dc5350502ff2b3d6a7f2de4d39996f4460e417`): Byte-for-byte identical to the canonical 6-face 3D soft-wall box $\mathcal{B}(e)$ module in *Physics v1.0 Appendix A (`v1.5`)* ([10.5281/zenodo.23534449](https://doi.org/10.5281/zenodo.23534449)).
3. [`lean/TypestateLifecycle.lean`](lean/TypestateLifecycle.lean) (**12 theorems**): Proves 5 request-lifecycle typestate and worker-epoch theorems (`oom_from_partial_init_is_poisoned`, `no_deref_after_partial_oom_abort`, `no_shutdown_uaf_on_poisoned_state`, `stale_epoch_read_rejected`, `typestate_and_epoch_security_certificate`), 3 v1.1.2 bridge theorems (`patankar_euler_step_in_box`, `psi_decay_floor_bound`, `merkle_dag_merge_commutative`), and 4 v1.2.0 deep-audit theorems (`patankar_strict_positivity_floor`, `lrsc_attention_lipschitz_error_bound`, `fence_seq_strict_monotonicity`, and `merkle_dag_semilattice_laws`).

---

## Double-PhD Red-Team Audit Board: All 10 Stress Resolutions (`25/25` Pytest Suite)

| Audit Probe | Resolution in `v1.2.0` (`shark_protocol/kernel.py`, `gateway.py` & `lean/TypestateLifecycle.lean`) | Verified By |
| :--- | :--- | :--- |
| **Problem 1 & Probe A** (Patankar-Euler Box Invariance & IEEE-754 Subnormal/FTZ Guard) | Clears $x_k$ from the denominator via $x_{k+1} = (x_k + h P x_{\max}) / (1 + h(P+D))$ with $10^{-12}$ Taylor cutoffs and enforces normal IEEE-754 float64 floor `FLOAT64_NORMAL_MIN = 2.2250738585072014e-308` whenever $x_k > 0$ or $P(x_k) > 0$. | Theorems 6 & 9, `test_15`, `test_21` |
| **Problem 2 & Probe B** ($\mathcal{P}_0 = 0$ Basin Separatrix & Multi-Tenant Saturation DoS Immunity) | Enforces Grönwall floor $\Psi(t+\Delta t) \ge \Psi(t)e^{-\mu_\Psi \Delta t}$, isolates each tenant in a dedicated `SharkProtocolEngine` (`get_tenant_engine`), and clamps waking gateway requests to $\mathcal{P}_0 \ge 1.0 \gg \mathcal{P}_{	ext{eff}}^{	ext{floor}} = 0.042350$. | Theorem 7, `test_16`, `test_22` |
| **Problem 3 & Probe C** (Sub-Threshold Null-Space $\eta_\perp \le 	au_{	ext{null}}$, Bandlimited Witness & Dual Seal) | Projects onto odd-ring channel filter $V_{	ext{ring}}$ ($\sigma_{\min}(S_{11}) = 0.18164624 > 0$), computes Lipschitz attention error bound $\|\Delta\operatorname{Attn}\|_2 \le L_W(1 + 2L_W^2/\sqrt{d_k})\eta_\perp$, and seals **both** `lrsc_sha256` and `uncompressed_ring_sha256` in every VRK claim. | Theorem 10, `test_17`, `test_23` |
| **Problem 4 & Probe D** (Free-Threaded Python PEP 703 / `--disable-gil` Lock Encapsulation) | Makes `_state`, `_is_zeroed`, and `_fence_seq` private with `@property` accessors and atomic `snapshot()` under `RequestSlot._lock`, enforcing strict lock order `WorkerEpochGuard._lock -> RequestSlot._lock`. | Theorem 11, `test_18`, `test_24` |
| **Problem 5 & Probe E** ($N$-Way Associative, Commutative & Idempotent Merkle-DAG Join) | Flattens intermediate merge nodes into canonical `leaf_frontier_tips` and `merged_claim_digests` set unions so $(A \sqcup B) \sqcup C = A \sqcup (B \sqcup C)$ and $A \sqcup A = A$ produce identical SHA-256 digests. | Theorems 8 & 12, `test_19`, `test_20`, `test_25` |

---

## What Is and Is Not Modelled (Epistemic Firewall)

- **Lifecycle Model Scope:** The theorems in `lean/TypestateLifecycle.lean` prove properties of the formal state-transition model, and `shark_protocol/kernel.py` enforces those invariants at the Python application layer. They are not a native C/PHP runtime patch, OS kernel memory protection mechanism, or hardware ARM64/x86 CPU cache-coherency protocol.
- **Gateway Verification Scope:** Only the deterministic offline verification path (`VRK_OFFLINE_SEALED_SIMULATION`) and local `127.0.0.1` loopback HTTP proxy are exercised and verified in CI. Live external cloud dispatch (`LIVE_API_DISPATCH` for Groq, Together AI, Google Gemini, and Hugging Face) is an optional runtime integration path requiring user API keys in `.env` and is not claimed as verified in CI.
- **Mathematical State Variable Scope:** $\Psi(t) \in [0,1]$ is strictly a bounded mathematical state variable of Eq. (4), not a claim of machine consciousness or sentience.

---

## Quickstart & Verification Commands

```bash
pip install -r requirements.txt
pip install -e .

# 1. Verify all 23 file hashes in MANIFEST_SHA256.txt:
sha256sum -c MANIFEST_SHA256.txt

# 2. Run the 25-test unit, integration & Double-PhD red-team stress suite:
pytest -v tests/

# 3. Run the CLI lifecycle & red-team self-audit:
shark-protocol --cli --audit-lifecycle

# 4. Launch the local loopback HTTP gateway server on http://127.0.0.1:8000:
shark-protocol --serve
```
