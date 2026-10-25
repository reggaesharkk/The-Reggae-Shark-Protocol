# The Reggae Shark Protocol (`v1.3.1` — Reviewer-Audited Edition)

**Author:** Prince Upadhyay ([ORCID: 0009-0002-1170-4487](https://orcid.org/0009-0002-1170-4487) · `starxshark@gmail.com`)  
**Repository:** [https://github.com/reggaesharkk/The-Reggae-Shark-Protocol](https://github.com/reggaesharkk/The-Reggae-Shark-Protocol)  
**Concept DOI:** [10.5281/zenodo.23618032](https://doi.org/10.5281/zenodo.23618032) · **Prior Version DOIs:** [10.5281/zenodo.23635351](https://doi.org/10.5281/zenodo.23635351) (`v1.2.0` / `v4`), [10.5281/zenodo.23624605](https://doi.org/10.5281/zenodo.23624605) (`v1.1.2` / `v3`), [10.5281/zenodo.23620074](https://doi.org/10.5281/zenodo.23620074) (`v1.1.0` / `v2`), [10.5281/zenodo.23618033](https://doi.org/10.5281/zenodo.23618033) (`v1.0.3` / `v1`)  
**Licenses:** **MIT License** (`LICENSE`) for all Python source code and Lean 4 formal proofs · **CC BY 4.0** for the specification manuscript (`paper/specification.tex` & `paper/specification.pdf`)

---

## 1. Architectural Overview & Epistemic Claim Firewall

The Reggae Shark Protocol (`v1.3.1`) is an application-layer verification kernel and multi-cloud AI execution gateway organized into four verification layers:

| Layer | Module / Artifact | Enforced Mathematical & Cryptographic Check |
|---|---|---|
| **Layer 1** | `shark_protocol/kernel.py`<br>`SECURITY.md` · `AUDIT_LOG.md` | **Ed25519-Signed VRK v0.3.1 Hash Chain, Signed Head Record & Subprocess Signer (`IsolatedSignerSubprocess`):** Requires an explicit 32-byte private seed (`SHARK_ED25519_SEED_HEX`) with the OpenSSL-backed `cryptography` package (no public default seed and no pure-Python fallback), requires a pinned `expected_pubkey` in `verify_chain_list`, supports append-only `.jsonl` persistence with `os.fsync` and signed `(head_index, ledger_length, head_hash)` head records to detect tail truncation, and supports child-process key isolation via `IsolatedSignerSubprocess`. |
| **Layer 1B** | `lean/TypestateLifecycle.lean`<br>`data/lean_transition_table.json` | **6-State Request-Lifecycle Automaton (15 Theorems) + Differential Trace Verification:** Proves inductive trace safety (`runTrace`) over arbitrary event lists with strictly absorbing `ZeroedFreed`, exports the 6×5 transition table via `#eval` to `data/lean_transition_table.json`, and verifies state-for-state equivalence between Lean and Python (`RequestSlot`) across random event traces (`test_36`). |
| **Layer 2** | `lean/ExistenceVerification.lean`<br>`lean/BoundaryVerification.lean`<br>`data/wp19_segments.json` | **4D Soft-Wall ODE Governor ($\mathcal{B}_4$, 26 Theorems), 200-Bit `mpmath.iv` Patankar Bridge & Illustrative WP19 Parameter Study:** Combines adaptive RK4, `float64` Patankar-Euler, and 200-bit outward-rounded `mpmath.iv` Patankar-Euler enclosures (`step_ode_patankar_mp_interval`, Theorem 13), plus an illustrative 120-segment Duhamel parameter study (`evaluate_wp19_piecewise_duhamel_study`, Theorem 15) loaded from `data/wp19_segments.json`. |
| **Layer 3 & 4** | `shark_protocol/kernel.py`<br>`shark_protocol/gateway.py` | **Bandlimited LRSC $11/99$ Projection, Perturbation Budget Scaling & Hardened Gateway:** Projects prompt contexts onto the $M=99, K=11$ odd-ring filter ($\sigma_{\min}(S_{11}) = 0.18164624 > 0$, [10.17605/OSF.IO/NM5BW](https://doi.org/10.17605/OSF.IO/NM5BW)), bounds perturbation scaling under an assumed local sensitivity factor $L$ (`perturbation_budget_scaling`, Theorem 10), binds HTTP tenants to Bearer tokens (`derive_tenant_from_token`), enforces per-tenant rate limits (HTTP `429`) and `64 KiB` payload caps (HTTP `413`), and fails closed (`GatewayDispatchError`) when live upstream calls fail. |

### Epistemic Claim Firewall (`Build. Attack. Falsify. Preserve.`)
- **Application-Layer Python & User-Space Subprocess vs. OS Ring-0:** `RequestSlot`, `WorkerEpochGuard`, and `IsolatedSignerSubprocess` enforce typestate invariants and separate process memory in user-space Python (`threading.RLock` and `subprocess.Popen`). They are not an OS ring-0 kernel module, hardware enclave, or C/PHP interpreter patch. Note that Theorem 14 (`projection_independent_of_secret`) is a definitional projection lemma; process isolation of the signing key rests on the runtime `subprocess.Popen` design and `test_32`.
- **Real Arithmetic in Lean vs. Runtime Interval Enclosures:** Lean 4 Theorems 6, 7, 9, 10, 13, and 15 are proved over $\mathbb{R}$; `step_ode_patankar_mp_interval` bridges discrete Patankar steps to $\mathbb{R}$ via 200-bit outward-rounded `mpmath.iv` intervals (`INTERVAL_CERTIFIED_RESULT`).
- **Illustrative WP19 Parameter Study vs. Continuum Navier-Stokes:** `evaluate_wp19_piecewise_duhamel_study` evaluates the 120-segment Duhamel recurrence on the assumed rates in `data/wp19_segments.json` (`NUMERICAL_OBSERVATION`). It does not certify the Navier-Stokes Galerkin chain unless per-segment rates are independently certified from Arb enclosures, and continuum 3D Navier-Stokes regularity remains `OPEN`.

---

## 2. Ed25519 Keypair Generation & Verifier Pinning (`Tasks A & B`)

In `v1.3.1`, no default signing seed is shipped in the source code, and the historical `v1.2.0` default seed (`SHA-256: 914f28ea...`, pubkey `e3ad81062fa39a869b798e3ab3a7195316dbe7de0e5e0da22a7ff4194065b74c`) is permanently revoked.

1. **Generate your own private signing seed and public verification key locally:**
```bash
python3 -c '
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
seed = os.urandom(32)
pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print("SHARK_ED25519_SEED_HEX (keep secret in env/password manager):", seed.hex())
print("PUBLIC_KEY_HEX (publish and pass as expected_pubkey):", pub.hex())
'
```
2. **Export `SHARK_ED25519_SEED_HEX` in your local environment before starting the engine or gateway:**
```bash
export SHARK_ED25519_SEED_HEX="<your_64_hex_private_seed>"
```
3. **Verify ledger records and signed head commitments with a pinned `expected_pubkey`:**
```python
ok, msg = SharkProtocolEngine.verify_chain_list(
    engine.ledger,
    expected_pubkey=engine.public_key_hex,
    signed_head=engine.sign_head_record(),
)
```
*(Note: Automated unit tests in `tests/test_core.py` use an explicit, clearly labelled untrusted test-only seed `UNTRUSTED_TEST_ONLY_SEED_HEX = "554e545255535445445f544553545f534545445f534841524b5f563133312121"` whose corresponding test-only public key is `21a399fd8101c13f88f39280b376e7f77688a68eb6d910fb5757762a3e544634` — never trust test-only keys in production).*

---

## 3. Canonical Lean 4 Provenance & CI Axiom Gate (`41 Theorems`)

The repository compiles **41 zero-`sorry` Lean 4 theorems** across three modules and verifies all 41 theorem axiom footprints via `lean/AxiomsCheck.lean` and `tools/check_lean_axioms.py`:
- `lean/BoundaryVerification.lean` (`9` theorems, SHA-256: `49229b6163b5a3a77dc83779a7dc5350502ff2b3d6a7f2de4d39996f4460e417`, byte-identical to Physics `v1.5` Appendix A [10.5281/zenodo.23534449](https://doi.org/10.5281/zenodo.23534449)).
- `lean/ExistenceVerification.lean` (`17` theorems, SHA-256: `eec9486803fb2e12f94c3ef966098acd31e4a66df8269ebe8cb59a937f7abcae`, byte-identical to *The Theory of Bounded Existence* `v1.0.0` [10.5281/zenodo.23608244](https://doi.org/10.5281/zenodo.23608244)).
- `lean/TypestateLifecycle.lean` (`15` theorems + `#eval dumpTransitionTableJson`).
- `lean/AxiomsCheck.lean`: Executes `#print axioms` on all 41 theorems (`9 + 17 + 15`), verified in CI by `tools/check_lean_axioms.py` to depend only on subsets of `{propext, Classical.choice, Quot.sound}` with zero `sorryAx`.

---

## 4. Quick Verification Commands

```bash
# 1. Verify SHA-256 manifest and Lean axiom registration (41/41 theorems):
sha256sum -c MANIFEST_SHA256.txt
python3 tools/check_lean_axioms.py --source-only

# 2. Run the full 38-test unit, red-team, differential, and axiom test suite:
python3 -m unittest discover -s tests -v

# 3. Run the CLI lifecycle and red-team self-audit:
python3 -m shark_protocol.cli --cli --audit-lifecycle
```
