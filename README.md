# The Reggae Shark Protocol (v1.3.0 -- Cross-Program 3-Track Upgrade Edition)

[![Concept DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23618032.svg)](https://doi.org/10.5281/zenodo.23618032)
[![Version DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23635351.svg)](https://doi.org/10.5281/zenodo.23635351)
[![License: MIT](https://img.shields.io/badge/Code_&_Lean_4-MIT-blue.svg)](LICENSE)
[![License: CC BY 4.0](https://img.shields.io/badge/Specification_PDF-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Lean 4](https://img.shields.io/badge/Lean_4-41_Theorems_(0_sorry)-brightgreen.svg)](lean/)
[![Tests](https://img.shields.io/badge/Pytest-34%2F34_Passing-brightgreen.svg)](tests/test_core.py)

**Author:** Prince Upadhyay ([ORCID: 0009-0002-1170-4487](https://orcid.org/0009-0002-1170-4487) | `starxshark@gmail.com`)  
**Release Version:** `v1.3.0` (Red-Team Tested Edition | Concept DOI: [10.5281/zenodo.23618032](https://doi.org/10.5281/zenodo.23618032) | Lineage DOIs: `v3` [10.5281/zenodo.23624605](https://doi.org/10.5281/zenodo.23624605), `v2` [10.5281/zenodo.23620074](https://doi.org/10.5281/zenodo.23620074), and `v1.0.3` [10.5281/zenodo.23618033](https://doi.org/10.5281/zenodo.23618033))  
**Licensing:** **MIT License** ([`LICENSE`](LICENSE)) for all Python source code and Lean 4 formal proofs; **CC BY 4.0** for the technical specification manuscript (`paper/specification.tex` and `paper/specification.pdf`).  
**Epistemic Standard:** `Build. Attack. Falsify. Preserve.`

---

## Architectural Overview (Four Verification Layers)

**The Reggae Shark Protocol (`v1.3.0`)** is an application-layer verification kernel and multi-cloud AI execution gateway that binds every prompt dispatch to four deterministic mathematical and cryptographic checks:

| Layer | Module / Artifact | Enforced Mathematical & Cryptographic Invariant |
| :--- | :--- | :--- |
| **Layer 1** | [`shark_protocol/kernel.py`](shark_protocol/kernel.py) | **Ed25519-Signed VRK v0.3.1 SHA-256 Chain & $N$-Way Associative Merkle-DAG Join (`intentseal-vrk-claim-v2`):** Commits every execution record to `prev_hash`, `parent_hashes`, `prompt_sha256`, `response_sha256`, `lrsc_sha256`, `uncompressed_ring_sha256`, on-disk verified `evidence_root`, and an RFC 8032 Ed25519 signature (`signer_pubkey`, `ed25519_signature`) anchored at the frozen VRK trust root `f010a99d...05a0d0f` ([10.5281/zenodo.23018459](https://doi.org/10.5281/zenodo.23018459)). |
| **Layer 1B** | [`lean/TypestateLifecycle.lean`](lean/TypestateLifecycle.lean) | **Typestate Request-Lifecycle & Worker-Epoch Automaton (15 Theorems, `0 sorry`) + Python RLock Synchronization:** Formalizes a 6-state request automaton (`UNINIT -> PARTIAL_INIT -> SEALED_ACTIVE -> SHUTDOWN_CLEAN -> ZEROED_FREED` with `OOM_ABORT -> ABORTED_POISONED` and absorbing `ZEROED_FREED`), inductive trace safety across arbitrary event sequences (`runTrace`), `slot_epoch == worker_epoch` isolation, and Python `WorkerEpochGuard._lock -> RequestSlot._lock` hierarchy. |
| **Layer 2** | [`lean/ExistenceVerification.lean`](lean/ExistenceVerification.lean) & [`lean/BoundaryVerification.lean`](lean/BoundaryVerification.lean) | **4D Soft-Wall ODE Cognitive Dynamics Governor ($\mathcal{B}_4$, 26 Theorems, `0 sorry`):** Evolves $(\gamma, H_{	ext{obs}}, \dot{I}, \Psi)$ inside $\mathcal{B}_4 = [0, 10] 	imes [0, 100] 	imes [0, \dot{I}_{\max,	ext{4D}}] 	imes [0, 1]$ using adaptive sub-stepped RK4, a subnormal-safe Patankar-Euler interval integrator (`step_ode_patankar_interval` with Python runtime float64 floor $2.225 	imes 10^{-308}$), and a fail-closed Grönwall basin separatrix floor guard (`evaluate_basin_separatrix_guard`). |
| **Layer 3** | `LRSCCompressor` ([`shark_protocol/kernel.py`](shark_protocol/kernel.py)) | **Bandlimited Low-Rank Spectral Context Memory (`LRSC` $11/99 = 1/9$):** Projects prompt context onto the $M=99$ odd-ring channel filter $V_{	ext{ring}}$ ($\sigma_{\min}(S_{11}) = 0.18164624 > 0$, [10.17605/OSF.IO/NM5BW](https://doi.org/10.17605/OSF.IO/NM5BW) & [10.17605/OSF.IO/JAK5X](https://doi.org/10.17605/OSF.IO/JAK5X)), breaks scalar-multiple normalization collisions across distinct prompts, evaluates a bounded-domain local attention sensitivity proxy (Kim, Papamakarios & Mnih, ICML 2021), and binds both compressed and uncompressed SHA-256 digests. |
| **Layer 4** | [`shark_protocol/gateway.py`](shark_protocol/gateway.py) | **Fail-Closed Multi-Tenant Gateway & Hardened `ThreadingHTTPServer`:** Bounds per-tenant ODE/ledger instances in an `OrderedDict` LRU cache (`max_tenants=128`), enforces waking basal sensory drive $\mathcal{P}_0 \ge 1.0 \gg 10/99$, sends Gemini API keys via the `x-goog-api-key` HTTP header, enforces HTTP 413 payload caps (`65536` bytes) and Bearer token auth, and raises `GatewayDispatchError` fail-closed if a configured live API call fails. |

---

## Canonical Lean 4 Provenance & Archive File Count (41 Zero-`sorry` Theorems)

This repository contains **24 tracked files in total: 23 SHA-256 hash-verified files plus [`MANIFEST_SHA256.txt`](MANIFEST_SHA256.txt)** (which cannot include its own hash). All three Lean 4 modules in [`lean/`](lean/) are compiled in CI via `lake build` with **zero `sorry` axioms, zero custom `axiom` declarations, and zero `nlinarith` heuristics**:

1. [`lean/ExistenceVerification.lean`](lean/ExistenceVerification.lean) (**17 theorems**, `SHA-256: eec9486803fb2e12f94c3ef966098acd31e4a66df8269ebe8cb59a937f7abcae`): Byte-for-byte identical to the canonical 8-face 4D box $\mathcal{B}_4$ module in *The Theory of Bounded Existence (`v1.0.0`)* ([10.5281/zenodo.23608244](https://doi.org/10.5281/zenodo.23608244)).
2. [`lean/BoundaryVerification.lean`](lean/BoundaryVerification.lean) (**9 theorems**, `SHA-256: 49229b6163b5a3a77dc83779a7dc5350502ff2b3d6a7f2de4d39996f4460e417`): Byte-for-byte identical to the canonical 6-face 3D soft-wall box $\mathcal{B}(e)$ module in *Physics v1.0 Appendix A (`v1.5`)* ([10.5281/zenodo.23534449](https://doi.org/10.5281/zenodo.23534449)).
3. [`lean/TypestateLifecycle.lean`](lean/TypestateLifecycle.lean) (**15 theorems**, each audited via `#print axioms`): Proves 5 inductive trace typestate, absorbing terminal `ZeroedFreed`, and worker-epoch theorems (`oom_from_partial_init_is_poisoned`, `no_deref_after_partial_oom_abort`, `no_shutdown_uaf_on_poisoned_state`, `stale_epoch_read_rejected`, `typestate_and_epoch_security_certificate`), 3 bridge theorems (`patankar_euler_step_in_box`, `psi_decay_floor_bound`, `merkle_dag_merge_commutative`), and 4 supplementary theorems (`patankar_strict_positivity_floor`, `lrsc_attention_lipschitz_error_bound`, `fence_seq_strict_monotonicity`, and `merkle_dag_semilattice_laws`).

---

## Five Core Verification Guards & Five Edge-Case Probes (`34/34` Pytest Suite)

| Verification Guard & Probe | Resolution in `v1.3.0` (`shark_protocol/kernel.py`, `gateway.py` & `lean/TypestateLifecycle.lean`) | Verified By |
| :--- | :--- | :--- |
| **Guard 1 & Probe A** (Patankar-Euler Box Invariance & Python Subnormal Floor) | Clears $x_k$ from the denominator via $x_{k+1} = (x_k + h P x_{\max}) / (1 + h(P+D))$ over $\mathbb{R}$ (Lean 4 Theorems 6 & 9) and enforces Python runtime float64 floor `FLOAT64_NORMAL_MIN = 2.2250738585072014e-308` whenever $x_k > 0$ or $P(x_k) > 0$. | Theorems 6 & 9, `test_15`, `test_21` |
| **Guard 2 & Probe B** (Pointwise Decay Bound, Bounded Tenant LRU & Waking Drive Floor) | Proves pointwise $d\Psi/dt \ge -\mu_\Psi \Psi$ in Lean 4 (Theorem 7, yielding $\Psi(t+\Delta t) \ge \Psi(t)e^{-\mu_\Psi \Delta t}$ via Grönwall), isolates tenants in a bounded `OrderedDict` LRU (`max_tenants=128`), and clamps waking gateway requests to $\mathcal{P}_0 \ge 1.0 \gg 0.042350$. | Theorem 7, `test_16`, `test_22`, `test_29` |
| **Guard 3 & Probe C** (Prompt/Response Commitment, Bandlimited Witness & Local Sensitivity Proxy) | Eliminates scalar-multiple normalization collisions across `"a"`, `"b"`, `"Z"`, `"aaaa"`, `"zzzz"`, extracts the bandlimited witness on $V_{	ext{ring}}$ ($\sigma_{\min}(S_{11}) = 0.18164624 > 0$), bounds the local sensitivity proxy on $\|	ilde{x}\|_2 \le 1$ (Kim et al., ICML 2021; Theorem 10), and seals `prompt_sha256`, `response_sha256`, `lrsc_sha256`, and `uncompressed_ring_sha256`. | Theorem 10, `test_17`, `test_23`, `test_27` |
| **Guard 4 & Probe D** (Inductive Trace Safety, Absorbing `ZEROED_FREED` & RLock Hierarchy) | Proves by induction over arbitrary event traces `evs : List LifecycleEvent` that `ZeroedFreed` is strictly absorbing and `{AbortedPoisoned, ZeroedFreed}` never reaches `SealedActive` or `ShutdownClean`, and enforces `WorkerEpochGuard._lock -> RequestSlot._lock` in Python. | Theorems 1--5 & 11, `test_18`, `test_24`, `test_30` |
| **Guard 5 & Probe E** (Ed25519 Signing, Multi-Parent Verification & Associative Merkle-DAG Join) | Signs every claim with RFC 8032 Ed25519, verifies on-disk evidence anchors and `evidence_root`, rejects forged multi-parent tail entries (`test_26`), and flattens merge nodes into canonical `leaf_frontier_tips` set unions so $(A \sqcup B) \sqcup C = A \sqcup (B \sqcup C)$ and $A \sqcup A = A$. | Theorems 8 & 12, `test_19`, `test_20`, `test_25`, `test_26`, `test_28` |

---

## Cross-Program 3-Track Upgrades in `v1.3.0` (Programs 05, 06, 08 & 10)

| Upgrade Track | Mathematical / Architectural Mechanism | Lean 4 & Runtime Verification |
| :--- | :--- | :--- |
| **Track A: Real Field ($\mathbb{R}$) vs. Float64 Interval Bridge** *(Programs 08 & 10)* | Bridges Lean 4's exact real arithmetic ($\mathbb{R}$) and runtime IEEE-754 `float64` via 200-bit (`dps=60`) outward-rounded `mpmath.iv` interval arithmetic (`step_ode_patankar_mp_interval` & `seal_interval_certified_patankar_claim`), certifying enclosure width $< 10^{-45}$ and `float64` drift $< 10^{-12}$ inside $\mathcal{B}_4$. | Theorem 13 (`patankar_interval_rounding_in_box`), `test_31` (`INTERVAL_CERTIFIED_RESULT`) |
| **Track B: Multi-Principal Subprocess Ed25519 Key Isolation** *(Programs 06 & 10)* | Separates the Ed25519 signing authority into an isolated OS child process (`IsolatedSignerSubprocess` via `subprocess.Popen`) communicating over a restricted JSON-RPC pipe (`PUBKEY`, `SIGN`, `SHUTDOWN`), scrubbing the private seed from the worker/gateway address space and rejecting key-export commands. | Theorem 14 (`principal_key_isolation_noninterference`), `test_32` |
| **Track C: 120-Segment Piecewise Duhamel Contraction Bridge** *(Programs 05 & 10)* | Replaces naive whole-horizon Grönwall error amplification ($e^{LT}\sum \delta_k$, preserved at $1.6364 \times 10^{14}$) with a 200-bit `mpmath.iv` 120-segment piecewise Duhamel recurrence $E_{k+1} = e^{\mu_{\text{eff}}\Delta t}E_k + \delta_k$ (`certify_wp19_piecewise_duhamel_bridge`), certifying suppression below the signed $C_{500}$ lower bound $5.7586 \times 10^9$ whenever $\mu_{\text{eff}} < \mu_{\text{crit}} \approx 22.95\,\text{s}^{-1}$ (while keeping unconditional continuum regularity `OPEN`). | Theorem 15 (`duhamel_piecewise_contraction_bound`), `test_33`, `test_34` |

---

## What Is and Is Not Modelled (Epistemic Firewall)

- **Lifecycle Model Scope:** The theorems in `lean/TypestateLifecycle.lean` prove multi-step trace properties of the formal state-transition model, and `shark_protocol/kernel.py` enforces those invariants and `threading.RLock` acquisition order at the Python application layer. They are not a native C/PHP runtime patch, OS kernel memory protection mechanism, or hardware CPU cache-coherency protocol.
- **Real Arithmetic vs. Runtime Floating-Point:** Theorems 6, 7, 9, and 10 in `lean/TypestateLifecycle.lean` are proved over $\mathbb{R}$; IEEE-754 float64 subnormal clamping at `FLOAT64_NORMAL_MIN` and numerical Grönwall floor checks are enforced in Python runtime code.
- **Gateway Verification Scope:** Only the deterministic offline verification path (`VRK_OFFLINE_SEALED_SIMULATION`) and local `127.0.0.1` loopback HTTP proxy are exercised and verified in CI. Live external cloud dispatch (`LIVE_API_DISPATCH` for Groq, Together AI, Google Gemini, and Hugging Face) requires user API keys in `.env` and fails closed with `GatewayDispatchError` if a configured upstream provider call fails.
- **Mathematical State Variable Scope:** $\Psi(t) \in [0,1]$ is strictly a bounded mathematical state variable of Eq. (4), not a claim of machine consciousness or sentience.

---

## Quickstart & Verification Commands

```bash
pip install -r requirements.txt
pip install -e .

# 1. Verify all 23 file hashes in MANIFEST_SHA256.txt:
sha256sum -c MANIFEST_SHA256.txt

# 2. Run the 34-test unit, integration & red-team stress suite:
pytest -v tests/

# 3. Run the CLI lifecycle & red-team self-audit:
shark-protocol --cli --audit-lifecycle

# 4. Launch the local loopback HTTP gateway server on http://127.0.0.1:8000:
shark-protocol --serve
```
