[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23620074.svg)](https://doi.org/10.5281/zenodo.23620074)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# The Shark Protocol (`v1.1.0` â€” Ironclad Edition)

**Verifiable, Proof-Carrying AI Execution OS & Multi-Cloud Security Gateway** governed by **IntentSeal VRK (`v0.3.1`) Hash-Chaining**, **Formal Typestate & Epoch Isolation (`php2shell` Class Immunity)**, **4D Soft-Wall ODE Cognitive Dynamics**, and **LRSC (`11/99`) Spectral Context Compression**.

**Author:** Prince Upadhyay â€” Independent Researcher ([ORCID: `0009-0002-1170-4487`](https://orcid.org/0009-0002-1170-4487) Â· `starxshark@gmail.com`)  
**Epistemic Standard:** `Build. Attack. Falsify. Preserve.`

---

## Executive Summary

As autonomous AI agents acquire tool-calling capabilities and direct access to external infrastructure, naive wrapper scripts fail under out-of-memory interrupts, cross-request state contamination, and unverified claim promotion. **The Shark Protocol (`v1.1.0`)** is a proof-carrying execution engine and multi-cloud security gateway where **every architectural claim in this README is backed 1-to-1 by executable code, automated tests, and 31 zero-`sorry` Lean 4 theorems**:

1. **Layer 1 â€” IntentSeal VRK (`v0.3.1`) Append-Only Hash-Chained Ledger (`shark_protocol/kernel.py`):**
   - Enforces the `intentseal-vrk-claim-v2` schema ([DOI: `10.5281/zenodo.23018459`](https://doi.org/10.5281/zenodo.23018459)) with mandatory `scope.applies_to` and `scope.does_not_imply` firewalls, typed evidence roles, and a tamper-evident SHA-256 `prev_hash` chain anchored at trust root `f010a99d78b360b8fd5dc9b727f21b898889c6e75e3093cc22d6f04d005a0d0f`.
2. **Layer 1B â€” Formal Typestate Request-Lifecycle & Worker-Epoch Isolation (`lean/TypestateLifecycle.lean` & `RequestSlot`):**
   - Machine-checked **5-theorem zero-`sorry` Lean 4 formalization** and runtime finite-state machine (`UNINIT -> PARTIAL_INIT -> SEALED_ACTIVE -> SHUTDOWN_CLEAN -> ZEROED_FREED`) eliminating `php2shell`-class vulnerabilities (`CVE-2026-109618` Out-Of-Memory partial-init jump corruption / shutdown Use-After-Free, and `CVE-2026-109619` cross-request stale global worker state) inside the gateway state machine.
3. **Layer 2 â€” 4D Soft-Wall ODE Cognitive Dynamics Governor (`lean/ExistenceVerification.lean` & `lean/BoundaryVerification.lean`):**
   - Integrates the smooth ($C^\infty$) 4D system $(\gamma, H_{\mathrm{obs}}, \dot{I}, \Psi)$ Eqs. (B.1)â€“(B.4) ([DOI: `10.5281/zenodo.23608244`](https://doi.org/10.5281/zenodo.23608244)) using boundary-layer adaptive RK4 sub-stepping ($\Delta t = 0.0005\,\mathrm{s}$ near soft walls) and verifies containment inside the compact box $\mathcal{B}_4 = [0,10]\times[0,100]\times[0,\dot{I}_{\max,4\mathrm{D}}]\times[0,1]$ on every step, backed by **17 zero-`sorry` Lean 4 theorems** in `lean/ExistenceVerification.lean` and **9 zero-`sorry` Lean 4 theorems** in `lean/BoundaryVerification.lean` ([DOI: `10.5281/zenodo.23534449`](https://doi.org/10.5281/zenodo.23534449)).
4. **Layer 3 â€” Low-Rank Spectral Context Memory (`LRSCCompressor` in `shark_protocol/kernel.py`):**
   - Projects prompt contexts onto the $M=99$ near-Nyquist odd-ring spectral basis ([DOI: `10.17605/OSF.IO/NM5BW`](https://doi.org/10.17605/OSF.IO/NM5BW)) and compresses them to the certified $K=11$ witness subset $S_{11} = \{0,1,3,42,43,44,45,46,47,48,49\}$ ($11/99 = 1/9$ spectral footprint, [DOI: `10.17605/OSF.IO/JAK5X`](https://doi.org/10.17605/OSF.IO/JAK5X)).
5. **Layer 4 â€” Fail-Closed Multi-Cloud Security Gateway & HTTP Server (`shark_protocol/gateway.py`):**
   - Live HTTP proxy server (`shark-protocol --serve` on `http://127.0.0.1:8000`) with `/v1/execute`, `/v1/health`, and `/v1/ledger/verify` endpoints, real HTTPS dispatch (`requests.post`) and automatic failover across **Groq**, **Together AI**, **Google Gemini**, and **Hugging Face**, and transparent `[VRK_OFFLINE_SEALED_SIMULATION]` reporting when API keys are unconfigured.

---

## Formal Lean 4 Verification Inventory (31 Theorems, Zero `sorry`)

| Lean 4 Module | Theorems | Scope & Verified Mathematical Guarantee |
|---|---|---|
| `lean/ExistenceVerification.lean` | **17** (`0 sorry`, `0 nlinarith`) | Proves `R_self_sq_nonneg`, $-M_{H,4\mathrm{D}} \le \dot{H}_{\mathrm{obs}} \le M_{H,4\mathrm{D}}$, linear comparison floors, all 8 face sign inequalities on $\mathcal{B}_4$, and `existence_box_8face_nagumo_certificate`. |
| `lean/BoundaryVerification.lean` | **9** (`0 sorry`, `0 nlinarith`) | Proves all 6 face/ceiling Nagumo conditions on the 3D soft-wall box $\mathcal{B}(e)$ and `compact_box_nagumo_certificate`. |
| `lean/TypestateLifecycle.lean` | **5** (`0 sorry`) | Proves `oom_from_partial_init_is_poisoned`, `no_deref_after_partial_oom_abort` (`CVE-2026-109618` knockout), `no_shutdown_uaf_on_poisoned_state`, `stale_epoch_read_rejected` (`CVE-2026-109619` knockout), and `typestate_and_epoch_security_certificate`. |

---

## Multi-Cloud API Gateway Configuration (4 Backends)

Configure your provider keys in `.env` (see `.env.example`):

```ini
GROQ_API_KEY=your_groq_api_key_here
TOGETHER_API_KEY=your_together_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
HUGGINGFACE_API_KEY=your_huggingface_api_key_here
```

- **Groq API:** `llama-3.3-70b-versatile`
- **Together AI:** `meta-llama/Llama-3.3-70B-Instruct-Turbo`
- **Google Gemini:** `gemini-1.5-flash`
- **Hugging Face API:** `mistralai/Mistral-7B-Instruct-v0.2`

*(When API keys are present, `MultiProviderGateway` executes live HTTPS calls with automatic failover across the four providers. When keys are absent, it executes the full 4-layer local verification pipeline and tags the response `dispatch_mode: "VRK_OFFLINE_SEALED_SIMULATION"` rather than faking a live network call.)*

---

## Quickstart, CLI, HTTP Server & Streamlit Dashboard

```bash
git clone https://github.com/reggaesharkk/The-Reggae-Shark-Protocol.git
cd The-Reggae-Shark-Protocol
pip install -r requirements.txt
pip install .

# 1. Run the 4-layer CLI execution & php2shell typestate knockout audit:
shark-protocol --cli --audit-php2shell

# 2. Run the full unit, integration & red-team pytest suite:
pytest -v tests/

# 3. Launch the local HTTP Security Gateway Proxy on http://127.0.0.1:8000:
shark-protocol --serve

# 4. Launch the interactive Streamlit 4D ODE & VRK Dashboard:
streamlit run shark_protocol/dashboard.py
```

---

## Claim-Boundary Firewall (`scope.does_not_imply`)

In strict adherence to the Reggae Shark Universe Portfolio Evidence Standard:
- **What this repository proves and certifies:** Machine-checked Lean 4 pointwise box invariance (`31` theorems across `ExistenceVerification.lean`, `BoundaryVerification.lean`, and `TypestateLifecycle.lean`), SHA-256 hash-chained `intentseal-vrk-claim-v2` tamper detection, fail-closed application-level typestate and worker-epoch isolation against `PARTIAL_INIT` OOM aborts and stale worker slots, and $11/99$ LRSC spectral context projection.
- **What this repository does NOT claim:** It is an application-layer verification kernel and API gatewayâ€”not an OS ring-0 hardware memory boundary, network-layer DDoS firewall, solution to open Millennium Prize problems, or claim of machine consciousness ($\Psi(t) \in [0,1]$ is strictly a dimensionless mathematical state variable of Eq. B.4).

---

## Citation & License

- **Technical Specification:** [`paper/specification.pdf`](paper/specification.pdf) (LaTeX source: [`paper/specification.tex`](paper/specification.tex))
- **Zenodo Archive DOI:** [10.5281/zenodo.23620074](https://doi.org/10.5281/zenodo.23620074)
- **License:** MIT License (`Copyright (c) 2026 Prince Upadhyay`).

