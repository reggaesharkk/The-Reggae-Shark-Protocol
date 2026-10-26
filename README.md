# The Reggae Shark Protocol (`v1.3.2`)

**Author:** Prince Upadhyay ([ORCID: 0009-0002-1170-4487](https://orcid.org/0009-0002-1170-4487) · `starxshark@gmail.com`)  
**Repository:** [https://github.com/reggaesharkk/The-Reggae-Shark-Protocol](https://github.com/reggaesharkk/The-Reggae-Shark-Protocol)  
**Umbrella Portfolio:** [https://github.com/reggaesharkk/Reggae-shark-universe-](https://github.com/reggaesharkk/Reggae-shark-universe-)  
**Concept DOI:** [10.5281/zenodo.23618032](https://doi.org/10.5281/zenodo.23618032)  
**Licenses:** **MIT License** (`LICENSE`) for all Python source code and Lean 4 formal proofs · **CC BY 4.0** for the specification manuscript (`paper/specification.tex` & `paper/specification.pdf`)

## 1. Architectural Overview & Epistemic Claim Firewall

The Reggae Shark Protocol (`v1.3.2`) is a self-contained verification kernel and multi-cloud AI execution gateway organized into four verification layers:

| Layer | Module / Artifact | Enforced Mathematical & Cryptographic Check |
|---|---|---|
| **Layer 1** | `shark_protocol/kernel.py`<br>`SECURITY.md`<br>`data/release_head.json` | **Ed25519-Signed VRK v0.3.1 Hash Chain, Timestamped Head Commitments & Stateful Subprocess Signer (`IsolatedSignerSubprocess`):** Requires an explicit 32-byte private seed (`SHARK_ED25519_SEED_HEX`) or child-read `seed_file` with the OpenSSL-backed `cryptography` package (no default seed and no pure-Python fallback), requires a pinned `expected_pubkey` in `verify_chain_list`, enforces mandatory `signed_head` (`intentseal-vrk-head-v2` with ISO-8601 UTC `issued_at`) and `min_length` in `verify_exported_ledger`, writes append-only `.jsonl` ledgers with `os.fsync`, and supports stateful child-process key isolation (`IsolatedSignerSubprocess` enforcing `prev_hash == last_signed_digest` in-child). |
| **Layer 1B** | `lean/TypestateLifecycle.lean`<br>`data/lean_transition_table.json` | **6-State Request-Lifecycle Automaton (16 Theorems) + Differential Trace Verification:** Proves inductive trace safety (`runTrace`) over arbitrary event lists with strictly absorbing `ZeroedFreed` and unique reachability of `SealedActive` from `Uninit` (`sealed_active_unique_trace_from_uninit`: `runTrace Uninit evs = SealedActive ↔ evs = [BeginInit, SealSuccess]`), diffs Lean's `#eval dumpTransitionTableJson` output against `data/lean_transition_table.json` in CI, and verifies state-for-state equivalence against Python `RequestSlot` (`test_36`). |
| **Layer 2** | `lean/ExistenceVerification.lean`<br>`lean/BoundaryVerification.lean`<br>`data/wp19_segments.json` | **4D Soft-Wall ODE Governor ($\mathcal{B}_4$, 26 Theorems), 200-Bit `mpmath.iv` Patankar Bridge & Illustrative WP19 Parameter Study:** Combines adaptive RK4, `float64` Patankar-Euler box checking (`inside_B4_checked`), and 200-bit outward-rounded `mpmath.iv` Patankar-Euler interval certification (`step_ode_patankar_mp_interval`, `inside_B4_mp_iv_certified`, Theorem 13), plus an illustrative 120-segment Duhamel parameter study (`evaluate_wp19_piecewise_duhamel_study`, Theorem 15) on `data/wp19_segments.json`. |
| **Layer 3 & 4** | `shark_protocol/kernel.py`<br>`shark_protocol/gateway.py` | **Bandlimited LRSC $11/99$ Projection, Perturbation Budget Scaling & Token-Authenticated Multi-Tenant Gateway:** Projects prompt contexts onto the $M=99, K=11$ odd-ring filter ($\sigma_{\min}(S_{11}) = 0.18164624 > 0$, [10.17605/OSF.IO/NM5BW](https://doi.org/10.17605/OSF.IO/NM5BW)), bounds perturbation scaling under an assumed local sensitivity factor $L \ge 0$ (`perturbation_budget_scaling`, Theorem 10), authenticates HTTP tenants via a constant-time token registry (`sha256(token) -> tenant_id`, rejecting unknown tokens with HTTP `401`), persists per-tenant ledgers on disk, returns HTTP `503` at `max_tenants` without evicting active ledgers, enforces per-tenant rate limits (HTTP `429`), `64 KiB` payload caps (HTTP `413`), and a `10.0s` socket timeout, and fails closed (`GatewayDispatchError`) when live upstream calls fail. |

### Epistemic Claim Firewall (`Build. Attack. Falsify. Preserve.`)
- **Application-Layer Python & User-Space Subprocess vs. OS Ring-0:** `RequestSlot`, `WorkerEpochGuard`, and `IsolatedSignerSubprocess` enforce typestate invariants and separate process memory in user-space Python (`threading.RLock` and `subprocess.Popen`). They are not an OS ring-0 kernel module, hardware enclave, or C/PHP interpreter patch. Theorem 14 (`projection_independent_of_secret`) is a definitional projection lemma; process isolation and forward-chain enforcement rest on the runtime `subprocess.Popen` design and `test_32` / `test_41`.
- **Real Arithmetic in Lean vs. Runtime `float64` Checks & 200-Bit Interval Enclosures:** Lean 4 Theorems 6, 7, 9, 10, 13, and 15 are proved over $\mathbb{R}$. In Python runtime code, `step_ode_patankar_interval` performs a fast `float64` 2-ULP box check (`inside_B4_checked`), whereas rigorous outward-rounded interval certification over $\mathbb{R}$ is performed by `step_ode_patankar_mp_interval` using 200-bit `mpmath.iv` arithmetic (`inside_B4_mp_iv_certified`, `INTERVAL_CERTIFIED_RESULT`).
- **Illustrative WP19 Parameter Study vs. Continuum Navier-Stokes:** `evaluate_wp19_piecewise_duhamel_study` evaluates the 120-segment Duhamel recurrence on the assumed segment rates in `data/wp19_segments.json` (`NUMERICAL_OBSERVATION`). The in-repo SHA-256 check (`a78a67c8ea8f4950dcf8bad6e76ebb7fe6362742ac1dbc63881cc14311d99319`) guards against accidental file corruption, while external tamper resistance is anchored by publishing the hash in the release notes and Zenodo record. It does not certify the Navier-Stokes Galerkin chain unless per-segment rates are independently certified from Arb enclosures, and continuum 3D Navier-Stokes regularity remains `OPEN`.

## 2. Keypair Generation, Subprocess Key Delivery & Exported Ledger Verification

No default signing seed is shipped in the codebase, and known public test seeds (`SHA-256: 914f28ea...`, pubkey `e3ad81062fa39a869b798e3ab3a7195316dbe7de0e5e0da22a7ff4194065b74c`) are blocked by a built-in denylist.

1. **Generate a private signing key file (`0600`) and public verification key locally:**
```bash
python3 -c '
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
seed = os.urandom(32)
Path("authority.key").write_bytes(seed)
os.chmod("authority.key", 0o600)
pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print("Saved 32-byte seed to authority.key (mode 0600)")
print("PUBLIC_KEY_HEX (publish and pass as expected_pubkey):", pub.hex())
'
```
2. **Sign with child-process key isolation (`IsolatedSignerSubprocess`) and verify exported ledgers with mandatory `signed_head` and `min_length`:**
```python
from pathlib import Path
from shark_protocol import IsolatedSignerSubprocess, SharkProtocolEngine

with IsolatedSignerSubprocess(seed_file=Path("authority.key")) as child_signer:
    engine = SharkProtocolEngine(signer=child_signer)
    engine.seal_claim("claim.1", "First verified execution record")
    head = engine.sign_head_record()
    ok, msg = SharkProtocolEngine.verify_exported_ledger(
        engine.ledger,
        signed_head=head,
        expected_pubkey=engine.public_key_hex,
        min_length=1,
    )
```
*(Note: Automated unit tests in `tests/test_core.py` and the reference fixture in `data/release_head.json` use an explicit untrusted test-only seed `UNTRUSTED_TEST_ONLY_SEED_HEX = "554e545255535445445f544553545f534545445f534841524b5f563133322121"` whose test-only public key is `7cae9b4572a0f32715fbd9e6aa7f476ccca38b23aabc717d8f8430df0fa56d5e` — never trust test-only keys in production).*

## 3. Canonical Lean 4 Provenance, CI Axiom Gate (`42 Theorems`) & Pinned Data Hashes

The repository compiles **42 zero-`sorry` Lean 4 theorems** across three modules (`leanprover/lean4:v4.15.0`) and verifies all 42 theorem axiom footprints plus the `#eval` transition table in CI via `lean/AxiomsCheck.lean` and `tools/check_lean_axioms.py`:
- `lean/BoundaryVerification.lean` (`9` theorems, SHA-256: `49229b6163b5a3a77dc83779a7dc5350502ff2b3d6a7f2de4d39996f4460e417`, byte-identical to Physics `v1.5` Appendix A [10.5281/zenodo.23534449](https://doi.org/10.5281/zenodo.23534449)).
- `lean/ExistenceVerification.lean` (`17` theorems, SHA-256: `eec9486803fb2e12f94c3ef966098acd31e4a66df8269ebe8cb59a937f7abcae`, byte-identical to *The Theory of Bounded Existence* `v1.0.0` [10.5281/zenodo.23608244](https://doi.org/10.5281/zenodo.23608244)).
- `lean/TypestateLifecycle.lean` (`16` theorems + `#eval dumpTransitionTableJson`, SHA-256: `3d798bf53652a04d33dcd366475e3b742daa7e894c200cec0b1d91e21140c005`).
- `lean/AxiomsCheck.lean` (`42` `#print axioms` checks, SHA-256: `b10821dca17fd6e5eceedabeefa566819e8d01fe9d9ddd69282c655860f54110`).
- `data/lean_transition_table.json` (`30` state-event entries diffed against Lean `#eval` in CI, SHA-256: `b70f5fb7e600a5a5957b08fae197543a7843115c6ce05938645cd96b1658cd5b`).
- `data/wp19_segments.json` (`120`-segment parameter study inputs, SHA-256: `a78a67c8ea8f4950dcf8bad6e76ebb7fe6362742ac1dbc63881cc14311d99319`).
- `data/release_head.json` (reference release head hash `RELEASE_REFERENCE_HEAD_HASH`: `866e1919b5a3e9e1e896496f735fdc94846e03497533b74f6fe3a5a96608ee5b`, head digest: `7a6019c7f42f4adad0ee32211412e133ccb85a3dd100790f6471bd94eb1dcd06`).

## 4. Quick Verification Commands

```bash
# 1. Verify SHA-256 manifest and Lean axiom registration (42/42 theorems):
sha256sum -c MANIFEST_SHA256.txt
python3 tools/check_lean_axioms.py --source-only

# 2. Run the full 42-test unit, differential, and security test suite:
python3 -W default -m unittest discover -s tests -v

# 3. Run the CLI lifecycle and verification self-test:
python3 -m shark_protocol.cli --cli --audit-lifecycle
```
