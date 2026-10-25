# Security Policy & Threat Model (`SECURITY.md`)

**Project:** The Reggae Shark Protocol (`v1.3.1`)  
**Maintainer:** Prince Upadhyay (`starxshark@gmail.com`, [ORCID: 0009-0002-1170-4487](https://orcid.org/0009-0002-1170-4487))  
**Repository:** [https://github.com/reggaesharkk/The-Reggae-Shark-Protocol](https://github.com/reggaesharkk/The-Reggae-Shark-Protocol)  
**Concept DOI:** [10.5281/zenodo.23618032](https://doi.org/10.5281/zenodo.23618032)

## 1. Protected Assets
1. **Ed25519 Authority Signing Seed (`SHARK_ED25519_SEED_HEX`):** 32-byte private key seed used to sign `intentseal-vrk-claim-v2` ledger entries and `intentseal-vrk-head-v1` head commitments. Never stored in the repository, `.env.example`, or CI logs.
2. **VRK v0.3.1 Hash-Chained Ledger & Signed Head (`SharkProtocolEngine.ledger`):** Append-only SHA-256 hash chain anchored at `f010a99d78b360b8fd5dc9b727f21b898889c6e75e3093cc22d6f04d005a0d0f` ([10.5281/zenodo.23018459](https://doi.org/10.5281/zenodo.23018459)), committing to `prompt_sha256`, `response_sha256`, `lrsc_sha256`, `uncompressed_ring_sha256`, on-disk `evidence_root`, and a signed `(head_index, ledger_length, head_hash)` record.
3. **Per-Request Payload & Worker Epoch State (`RequestSlot`, `WorkerEpochGuard`):** In-memory request payload dictionary protected by the 6-state lifecycle automaton (`UNINIT -> PARTIAL_INIT -> SEALED_ACTIVE -> SHUTDOWN_CLEAN -> ZEROED_FREED`, with `OOM_ABORT -> ABORTED_POISONED`) and monotonic worker-epoch checks (`slot_epoch == worker_epoch`).
4. **Upstream Cloud Provider API Keys (`GROQ_API_KEY`, `TOGETHER_API_KEY`, `GEMINI_API_KEY`, `HUGGINGFACE_API_KEY`):** External credentials loaded from local environment variables.

## 2. Adversary Model
- **A1 — Unauthenticated Ledger Forger / Chain Rewriter:** Attempts to append a forged single-parent or multi-parent tail entry, rewrite historical entries and recompute SHA-256 digests without the authority private seed, sign with an arbitrary attacker key, sign with the retired `v1.2.0` public seed, or truncate the tail of an existing ledger.
- **A2 — Malicious / Compromised Tenant Client:** Sends oversized HTTP bodies (`> 64 KiB`), high-frequency request bursts exceeding the per-tenant sliding-window rate limit, spoofed `tenant_id` fields in JSON bodies when authenticated via Bearer token, or adversarial zero-drive (`P_0 = 0`) inputs.
- **A3 — Concurrent In-Process Worker Race / Stale Epoch Reader:** Attempts to read a request slot from a prior worker epoch (`slot_epoch != worker_epoch`), dereference a `PARTIAL_INIT` or `ABORTED_POISONED` slot after an exception/OOM abort, or mutate a terminal `ZEROED_FREED` slot.
- **A4 — In-Process Worker Memory Inspection Against Isolated Signer (`Track B`):** Attempts to read the Ed25519 private signing seed from the parent worker/gateway Python object graph when signing is delegated to `IsolatedSignerSubprocess` or via an unauthorized IPC command (`EXPORT_KEY`).

## 3. Trust Assumptions & Architectural Controls
- **Mandatory Key Configuration & Constant-Time Cryptography (`Task A`):** `Ed25519AuthoritySigner` requires the OpenSSL-backed `cryptography` package (`Ed25519PrivateKey` / `Ed25519PublicKey`) and refuses to start (`RuntimeError`) if no seed is supplied via `seed` or `SHARK_ED25519_SEED_HEX`. The retired `v1.2.0` default seed (`SHA-256: 914f28ea...`) and its public key (`e3ad8106...`) are permanently revoked in code.
- **Pinned Public-Key Verification & Signed Head Commitments (`Task B`):** `SharkProtocolEngine.verify_chain_list` requires `expected_pubkey` as a mandatory keyword-only argument (accepting a pinned 64-hex public key or trust set), verifies every entry and embedded merge record against that pinned trust set, persists entries to an append-only `.jsonl` file with `os.fsync`, and verifies `signed_head` (`intentseal-vrk-head-v1`) to detect tail truncation.
- **Token-Bound Tenants, Bounded LRU & Sliding-Window Rate Limiting (`Layer 4`):** `MultiProviderGateway` caps active tenant engines in an `OrderedDict` LRU cache (`max_tenants=128`), enforces a per-tenant sliding-window rate limit (`rate_limit_per_window=120` per `60s`, HTTP `429`), binds HTTP tenant identity to the Bearer token (`derive_tenant_from_token`), sends Gemini keys exclusively via `x-goog-api-key`, caps HTTP payloads at `65,536` bytes (HTTP `413`), and fails closed (`GatewayDispatchError`) on upstream live dispatch failure.

## 4. Explicit Non-Goals (`does_not_imply`)
- **Not an OS Ring-0 Kernel or Hardware Enclave:** `RequestSlot`, `WorkerEpochGuard`, and `IsolatedSignerSubprocess` operate in user-space Python (`threading.RLock` and `subprocess.Popen` pipes). They do not protect against a root/administrator attacker on the host OS (`ptrace`, `/proc/<pid>/mem`), hardware side channels, or native C/PHP interpreter memory corruption.
- **Not a Global Lipschitz Proof for Unbounded Softmax Attention:** Theorem 10 (`perturbation_budget_scaling`) proves linear scaling `0 <= L * eta_perp <= L * tau_null` for an assumed local parameter `L >= 0`.
- **Not an Unconditional Continuum Navier-Stokes Proof:** `evaluate_wp19_piecewise_duhamel_study` is an illustrative finite-segment parameter study loaded from `data/wp19_segments.json`.
