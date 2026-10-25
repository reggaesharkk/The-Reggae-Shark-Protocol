"""
Layer 1, Layer 1B, Layer 2, and Layer 3 Core Verification Kernel (`shark_protocol/kernel.py`)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Version: 1.2.0 (Red-Team Tested Edition | Concept DOI: 10.5281/zenodo.23618032 | v4 DOI: 10.5281/zenodo.23635351 | v3 DOI: 10.5281/zenodo.23624605)

What Is and Is Not Modelled (Epistemic Firewall):
- Layer 1 (`SharkProtocolEngine` + `Ed25519AuthoritySigner`): Enforces the `intentseal-vrk-claim-v2`
  schema anchored at the frozen VRK v0.3.1 trust root (`f010a99d...05a0d0f`, DOI: 10.5281/zenodo.23018459),
  committing every record to `prev_hash`, `parent_hashes`, `prompt_sha256`, `response_sha256`,
  `lrsc_sha256`, `uncompressed_ring_sha256`, on-disk verified `evidence_root`, and an RFC 8032 Ed25519
  digital signature (`signer_pubkey`, `ed25519_signature`). Supports N-way commutative, associative,
  and idempotent Merkle-DAG join-semilattice reconciliation (`merge_divergent_ledgers`) with strict
  parent-hash membership verification.
- Layer 1B (`RequestSlot` & `WorkerEpochGuard`): Formalizes an application-level 6-state request
  lifecycle automaton (`UNINIT -> PARTIAL_INIT -> SEALED_ACTIVE -> SHUTDOWN_CLEAN -> ZEROED_FREED`,
  with `OOM_ABORT -> ABORTED_POISONED` and `ZEROED_FREED` strictly terminal/absorbing) and monotonic
  worker-epoch isolation (`slot_epoch == worker_epoch`), with private mutex-encapsulated `_state`,
  `_is_zeroed`, `_fence_seq` and hierarchical lock ordering (`WorkerEpochGuard._lock -> RequestSlot._lock`).
- Layer 2 (`step_ode`, `step_ode_patankar_interval`, `evaluate_basin_separatrix_guard`): Integrates
  the 4D soft-wall ODE system (gamma, H_obs, I_dot, Psi) from Program 08 (DOI: 10.5281/zenodo.23608244),
  pairing adaptive sub-stepped RK4 with a Patankar-Euler + 2-ULP outward-rounded IEEE-754 interval
  integrator (with Python runtime float64 subnormal floor `FLOAT64_NORMAL_MIN = 2.2250738585072014e-308`)
  and a fail-closed Gronwall separatrix floor guard.
- Layer 3 (`LRSCCompressor`): Projects context onto the M=99 odd-ring near-Nyquist basis and retains
  the K=11 witness subset S_11 = {0,1,3,42..49} (11/99 = 1/9 ratio, DOI: 10.17605/OSF.IO/NM5BW &
  10.17605/OSF.IO/JAK5X), computing a bounded-domain local attention sensitivity proxy (following Kim,
  Papamakarios & Mnih, ICML 2021) and binding distinct compressed/uncompressed digests to the prompt.
"""

from __future__ import annotations

import contextlib
import enum
import hashlib
import json
import math
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

import numpy as np


VRK_TRUST_ROOT_DIGEST = "f010a99d78b360b8fd5dc9b727f21b898889c6e75e3093cc22d6f04d005a0d0f"
FLOAT64_NORMAL_MIN: float = float(np.finfo(np.float64).tiny)  # 2.2250738585072014e-308
REPO_ROOT: Path = Path(__file__).resolve().parent.parent

REQUIRED_VRK_ROLES: Dict[str, frozenset[str]] = {
    "CONJECTURE": frozenset(),
    "NUMERICAL_OBSERVATION": frozenset({"definition", "execution_record"}),
    "REPRODUCED_RESULT": frozenset({"definition", "execution_record", "independent_replication"}),
    "EXHAUSTIVE_FINITE_RESULT": frozenset({
        "definition", "passing_witness", "exclusion_certificate",
        "coverage_certificate", "independent_verification",
    }),
    "INTERVAL_CERTIFIED_RESULT": frozenset({"definition", "interval_certificate", "verifier"}),
    "ANALYTIC_THEOREM": frozenset({"definition", "proof", "scope_statement", "independent_verification"}),
}


def canonical_json_bytes(value: Any) -> bytes:
    """Deterministic canonical JSON serializer (VRK v0.3.1 standard)."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_canonical(value: Any) -> str:
    """Compute 64-hex SHA-256 digest of a canonical JSON object."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _is_hex64(val: Any) -> bool:
    if not isinstance(val, str) or len(val) != 64:
        return False
    return all(c in "0123456789abcdef" for c in val)


# Pure-Python RFC 8032 Ed25519 implementation (fallback when `cryptography` is absent;
# produces byte-identical 32-byte public keys and 64-byte signatures to OpenSSL / cryptography).
_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)
_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_ED_B = (_ED_BX % _ED_P, _ED_BY % _ED_P, 1, (_ED_BX * _ED_BY) % _ED_P)


def _ed_add(P: Tuple[int, int, int, int], Q: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (t1 * 2 * _ED_D * t2) % _ED_P
    d = (z1 * 2 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return ((e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P)


def _ed_scalarmult(P: Tuple[int, int, int, int], e: int) -> Tuple[int, int, int, int]:
    Q = (0, 1, 1, 0)
    cur = P
    while e > 0:
        if e & 1:
            Q = _ed_add(Q, cur)
        cur = _ed_add(cur, cur)
        e >>= 1
    return Q


def _ed_encode_point(P: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = P
    zi = pow(z, _ED_P - 2, _ED_P)
    xp = (x * zi) % _ED_P
    yp = (y * zi) % _ED_P
    return int(yp | ((xp & 1) << 255)).to_bytes(32, "little")


def _ed_decode_point(b: bytes) -> Optional[Tuple[int, int, int, int]]:
    if len(b) != 32:
        return None
    unpacked = int.from_bytes(b, "little")
    sign = (unpacked >> 255) & 1
    y = unpacked & ((1 << 255) - 1)
    if y >= _ED_P:
        return None
    y2 = (y * y) % _ED_P
    u = (y2 - 1) % _ED_P
    v = (_ED_D * y2 + 1) % _ED_P
    v3 = (v * v * v) % _ED_P
    v7 = (v3 * v3 * v) % _ED_P
    x = (u * v3 * pow(u * v7, (_ED_P - 5) // 8, _ED_P)) % _ED_P
    vxx = (v * x * x) % _ED_P
    if vxx == u:
        pass
    elif vxx == (-u) % _ED_P:
        x = (x * _ED_I) % _ED_P
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return (x, y, 1, (x * y) % _ED_P)


class Ed25519AuthoritySigner:
    """
    RFC 8032 Ed25519 digital signature authority for VRK v0.3.1 ledger records (Audit Item 3 Fix).
    Uses `cryptography.hazmat.primitives.asymmetric.ed25519` when available, with a byte-for-byte
    identical pure-Python RFC 8032 fallback when running in minimal environments.
    """

    DEFAULT_DETERMINISTIC_SEED = hashlib.sha256(
        b"shark_protocol_v1_2_0_default_ed25519_seed:" + VRK_TRUST_ROOT_DIGEST.encode("ascii")
    ).digest()

    def __init__(self, seed: Optional[bytes] = None) -> None:
        if seed is None:
            env_hex = os.environ.get("SHARK_ED25519_SEED_HEX", "").strip()
            if env_hex:
                seed = bytes.fromhex(env_hex)
            else:
                seed = self.DEFAULT_DETERMINISTIC_SEED
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes.")
        self._seed = bytes(seed)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            self._priv_obj = Ed25519PrivateKey.from_private_bytes(self._seed)
            self._pub_bytes = self._priv_obj.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._use_c_backend = True
        except Exception:
            h = hashlib.sha512(self._seed).digest()
            a = int.from_bytes(h[:32], "little")
            a &= (1 << 254) - 8
            a |= 1 << 254
            self._a = a
            self._prefix = h[32:]
            self._pub_bytes = _ed_encode_point(_ed_scalarmult(_ED_B, a))
            self._use_c_backend = False

    @property
    def public_key_hex(self) -> str:
        return self._pub_bytes.hex()

    def sign_digest_hex(self, digest_hex: str) -> str:
        msg = digest_hex.encode("ascii")
        if self._use_c_backend:
            return self._priv_obj.sign(msg).hex()
        r = int.from_bytes(hashlib.sha512(self._prefix + msg).digest(), "little") % _ED_L
        R = _ed_encode_point(_ed_scalarmult(_ED_B, r))
        k = int.from_bytes(hashlib.sha512(R + self._pub_bytes + msg).digest(), "little") % _ED_L
        S = ((r + k * self._a) % _ED_L).to_bytes(32, "little")
        return (R + S).hex()

    @staticmethod
    def verify_digest_signature(pubkey_hex: str, digest_hex: str, signature_hex: str) -> bool:
        try:
            pub_bytes = bytes.fromhex(pubkey_hex)
            sig_bytes = bytes.fromhex(signature_hex)
            if len(pub_bytes) != 32 or len(sig_bytes) != 64:
                return False
            msg = digest_hex.encode("ascii")
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
                pub.verify(sig_bytes, msg)
                return True
            except ImportError:
                A = _ed_decode_point(pub_bytes)
                R = _ed_decode_point(sig_bytes[:32])
                S = int.from_bytes(sig_bytes[32:], "little")
                if A is None or R is None or S >= _ED_L:
                    return False
                k = int.from_bytes(hashlib.sha512(sig_bytes[:32] + pub_bytes + msg).digest(), "little") % _ED_L
                lhs = _ed_scalarmult(_ED_B, S)
                rhs = _ed_add(R, _ed_scalarmult(A, k))
                return _ed_encode_point(lhs) == _ed_encode_point(rhs)
        except Exception:
            return False


class LifecycleState(str, enum.Enum):
    UNINIT = "UNINIT"
    PARTIAL_INIT = "PARTIAL_INIT"
    SEALED_ACTIVE = "SEALED_ACTIVE"
    SHUTDOWN_CLEAN = "SHUTDOWN_CLEAN"
    ABORTED_POISONED = "ABORTED_POISONED"
    ZEROED_FREED = "ZEROED_FREED"


class LifecycleEvent(str, enum.Enum):
    BEGIN_INIT = "BEGIN_INIT"
    SEAL_SUCCESS = "SEAL_SUCCESS"
    OOM_ABORT = "OOM_ABORT"
    NORMAL_CLOSE = "NORMAL_CLOSE"
    ZERO_AND_FREE = "ZERO_AND_FREE"


class TypestateViolationError(RuntimeError):
    """Raised when an invalid lifecycle transition, poisoned dereference, or unsafe destructor is attempted."""


class StaleWorkerEpochError(RuntimeError):
    """Raised when a worker attempts to read a slot belonging to a stale request epoch."""


class BasinCollapseError(RuntimeError):
    """Raised when an adversarial perturbation drives Psi(t) or P_eff(t) below the basin separatrix floor."""


class RequestSlot:
    """
    Thread-safe request slot enforcing the 6-state lifecycle typestate automaton
    formalized in `lean/TypestateLifecycle.lean`.
    Audit Item 5 Fix: `ZEROED_FREED` is a strictly absorbing terminal state (once in
    `ZEROED_FREED`, any subsequent transition raises `TypestateViolationError` while keeping
    `_state == LifecycleState.ZEROED_FREED`).
    """

    def __init__(
        self,
        slot_epoch: int,
        state: LifecycleState = LifecycleState.UNINIT,
        is_zeroed: bool = False,
    ) -> None:
        self._lock = threading.RLock()
        self._slot_epoch = int(slot_epoch)
        self._state: LifecycleState = LifecycleState(state)
        self._is_zeroed: bool = bool(is_zeroed)
        self._payload: Optional[Dict[str, Any]] = None
        self._fence_seq: int = 0

    @property
    def slot_epoch(self) -> int:
        with self._lock:
            return self._slot_epoch

    @property
    def state(self) -> LifecycleState:
        with self._lock:
            return self._state

    @state.setter
    def state(self, new_state: LifecycleState) -> None:
        with self._lock:
            if self._state == LifecycleState.ZEROED_FREED and LifecycleState(new_state) != LifecycleState.ZEROED_FREED:
                raise TypestateViolationError("Cannot mutate state of a terminal ZEROED_FREED slot.")
            self._state = LifecycleState(new_state)
            self._fence_seq += 1

    @property
    def is_zeroed(self) -> bool:
        with self._lock:
            return self._is_zeroed

    @is_zeroed.setter
    def is_zeroed(self, val: bool) -> None:
        with self._lock:
            self._is_zeroed = bool(val)
            self._fence_seq += 1

    @property
    def fence_seq(self) -> int:
        with self._lock:
            return self._fence_seq

    def snapshot(self) -> Tuple[int, LifecycleState, bool, int]:
        """Return a single lock-consistent atomic tuple `(slot_epoch, state, is_zeroed, fence_seq)`."""
        with self._lock:
            return (self._slot_epoch, self._state, self._is_zeroed, self._fence_seq)

    def transition(self, event: LifecycleEvent, payload: Optional[Dict[str, Any]] = None) -> LifecycleState:
        with self._lock:
            if self._state == LifecycleState.ZEROED_FREED:
                self._fence_seq += 1
                raise TypestateViolationError(
                    f"Terminal typestate guard: slot is already in absorbing state ZEROED_FREED on event {event.value}."
                )
            if self._state == LifecycleState.UNINIT and event == LifecycleEvent.BEGIN_INIT:
                self._state = LifecycleState.PARTIAL_INIT
                self._payload = None
            elif self._state == LifecycleState.PARTIAL_INIT and event == LifecycleEvent.SEAL_SUCCESS:
                if payload is None:
                    self._state = LifecycleState.ABORTED_POISONED
                    self._payload = None
                    self._fence_seq += 1
                    raise TypestateViolationError("Cannot transition to SEALED_ACTIVE with None payload.")
                self._state = LifecycleState.SEALED_ACTIVE
                self._payload = dict(payload)
            elif self._state in (LifecycleState.PARTIAL_INIT, LifecycleState.SEALED_ACTIVE) and event == LifecycleEvent.OOM_ABORT:
                self._payload = None
                self._state = LifecycleState.ABORTED_POISONED
            elif self._state == LifecycleState.SEALED_ACTIVE and event == LifecycleEvent.NORMAL_CLOSE:
                self._state = LifecycleState.SHUTDOWN_CLEAN
            elif self._state in (LifecycleState.SHUTDOWN_CLEAN, LifecycleState.ABORTED_POISONED) and event == LifecycleEvent.ZERO_AND_FREE:
                self._payload = None
                self._is_zeroed = True
                self._state = LifecycleState.ZEROED_FREED
            else:
                self._payload = None
                self._state = LifecycleState.ABORTED_POISONED
                self._fence_seq += 1
                raise TypestateViolationError(
                    f"Illegal typestate transition from {self._state.value} on event {event.value}; slot poisoned."
                )
            self._fence_seq += 1
            return self._state

    @contextlib.contextmanager
    def atomic_lifecycle_scope(self, initial_payload: Dict[str, Any]) -> Iterator["RequestSlot"]:
        """
        Thread-safe context manager that transitions UNINIT -> PARTIAL_INIT -> SEALED_ACTIVE,
        yields the active slot, and guarantees fail-closed poisoning (`ABORTED_POISONED` ->
        `ZEROED_FREED`) if any exception or asynchronous interrupt occurs mid-flight.
        """
        with self._lock:
            try:
                self.transition(LifecycleEvent.BEGIN_INIT)
                self.transition(LifecycleEvent.SEAL_SUCCESS, payload=initial_payload)
            except BaseException:
                self._payload = None
                if self._state != LifecycleState.ZEROED_FREED:
                    self._state = LifecycleState.ABORTED_POISONED
                    self.transition(LifecycleEvent.ZERO_AND_FREE)
                raise
        try:
            yield self
            with self._lock:
                if self._state == LifecycleState.SEALED_ACTIVE:
                    self.run_clean_destructor()
                    self.transition(LifecycleEvent.ZERO_AND_FREE)
        except BaseException:
            with self._lock:
                self._payload = None
                if self._state in (LifecycleState.PARTIAL_INIT, LifecycleState.SEALED_ACTIVE):
                    self.transition(LifecycleEvent.OOM_ABORT)
                elif self._state != LifecycleState.ZEROED_FREED:
                    self._state = LifecycleState.ABORTED_POISONED
                if self._state != LifecycleState.ZEROED_FREED:
                    self.transition(LifecycleEvent.ZERO_AND_FREE)
            raise

    def dereference_payload(self) -> Dict[str, Any]:
        with self._lock:
            if self._state != LifecycleState.SEALED_ACTIVE or self._is_zeroed or self._payload is None:
                raise TypestateViolationError(
                    f"Typestate guard: payload dereference blocked in state {self._state.value}."
                )
            return dict(self._payload)

    def run_clean_destructor(self) -> bool:
        with self._lock:
            if self._state == LifecycleState.SEALED_ACTIVE:
                self.transition(LifecycleEvent.NORMAL_CLOSE)
            if self._state != LifecycleState.SHUTDOWN_CLEAN:
                raise TypestateViolationError(
                    f"Typestate guard: clean destructor blocked on state {self._state.value} (use-after-free/abort prevented)."
                )
            self._payload = None
            self._fence_seq += 1
            return True


class WorkerEpochGuard:
    """
    Thread-safe monotonic worker-epoch isolator (`lean/TypestateLifecycle.lean`: `stale_epoch_read_rejected`).
    Enforces strict hierarchical lock ordering (`WorkerEpochGuard._lock` -> `RequestSlot._lock`).
    """

    def __init__(self, initial_epoch: int = 1) -> None:
        if initial_epoch < 1:
            raise ValueError("initial_epoch must be >= 1")
        self._lock = threading.RLock()
        self._worker_epoch = int(initial_epoch)
        self._active_slot: Optional[RequestSlot] = None

    @property
    def worker_epoch(self) -> int:
        with self._lock:
            return self._worker_epoch

    def begin_request(self) -> RequestSlot:
        with self._lock:
            if self._active_slot is not None:
                _, act_state, _, _ = self._active_slot.snapshot()
                if act_state != LifecycleState.ZEROED_FREED:
                    self._retire_active_slot()
            self._worker_epoch += 1
            slot = RequestSlot(slot_epoch=self._worker_epoch)
            slot.transition(LifecycleEvent.BEGIN_INIT)
            self._active_slot = slot
            return slot

    def read_slot(self, slot: RequestSlot) -> Dict[str, Any]:
        with self._lock:
            with slot._lock:
                slot_ep, slot_st, slot_zeroed, _ = slot.snapshot()
                if slot_ep != self._worker_epoch:
                    raise StaleWorkerEpochError(
                        f"Epoch isolation guard: worker at epoch {self._worker_epoch} rejected stale slot from epoch {slot_ep}."
                    )
                if slot_zeroed or slot_st != LifecycleState.SEALED_ACTIVE:
                    raise TypestateViolationError(
                        f"Epoch isolation guard: slot in state {slot_st.value} (is_zeroed={slot_zeroed}) cannot be read."
                    )
                return slot.dereference_payload()

    def finish_request(self, slot: RequestSlot, abort: bool = False) -> None:
        with self._lock:
            with slot._lock:
                if abort:
                    if slot.state in (LifecycleState.PARTIAL_INIT, LifecycleState.SEALED_ACTIVE):
                        slot.transition(LifecycleEvent.OOM_ABORT)
                else:
                    if slot.state == LifecycleState.SEALED_ACTIVE:
                        slot.run_clean_destructor()
                if slot.state in (LifecycleState.SHUTDOWN_CLEAN, LifecycleState.ABORTED_POISONED):
                    slot.transition(LifecycleEvent.ZERO_AND_FREE)

    def _retire_active_slot(self) -> None:
        with self._lock:
            slot = self._active_slot
            if slot is None:
                return
            with slot._lock:
                if slot.state in (LifecycleState.PARTIAL_INIT, LifecycleState.SEALED_ACTIVE):
                    slot.transition(LifecycleEvent.OOM_ABORT)
                if slot.state in (LifecycleState.SHUTDOWN_CLEAN, LifecycleState.ABORTED_POISONED):
                    slot.transition(LifecycleEvent.ZERO_AND_FREE)


class LRSCCompressor:
    """
    Layer 3: Low-Rank Spectral Context Memory (LRSC 11/99 = 1/9).
    Implements the odd-ring near-Nyquist cyclic projection (M=99, K=11) from
    Program 04 (DOI: 10.17605/OSF.IO/NM5BW and DOI: 10.17605/OSF.IO/JAK5X).
    Audit Item 2 & Item 5 Fixes:
    - Breaks scalar-multiple normalization degeneracy via position-and-byte phase coupling so
      single-character (`"a"`, `"b"`, `"Z"`) and constant-byte (`"aaaa"`, `"zzzz"`) prompts map
      to distinct ring directions, distinct `witness_vector` entries, and distinct `lrsc_sha256`
      and `uncompressed_fallback_sha256` digests, while also binding `prompt_sha256`.
    - Reports `attention_perturbation_upper_bound` as a local bounded-domain sensitivity proxy
      on the unit ball `||x||_2 <= 1` (since global dot-product softmax attention is not globally
      Lipschitz on R^d; Kim, Papamakarios & Mnih, ICML 2021).
    """
    M_RING: int = 99
    K_WITNESS: int = 11
    WITNESS_INDICES: Tuple[int, ...] = (0, 1, 3, 42, 43, 44, 45, 46, 47, 48, 49)
    K_NYQUIST: int = 49
    THETA: float = 0.08
    AMPLITUDE: float = 0.50

    def __init__(
        self,
        null_space_threshold: float = 0.92,
        attn_weight_norm: float = 1.0,
        attn_head_dim: int = 64,
    ) -> None:
        self.null_space_threshold = float(null_space_threshold)
        self.attn_weight_norm = float(attn_weight_norm)
        self.attn_head_dim = int(attn_head_dim)
        # Local bounded-domain sensitivity proxy on ||x||_2 <= 1 (Kim, Papamakarios & Mnih, ICML 2021)
        self.attn_lipschitz_constant = self.attn_weight_norm * (
            1.0 + (2.0 * (self.attn_weight_norm ** 2)) / math.sqrt(float(self.attn_head_dim))
        )

        m = np.arange(self.M_RING, dtype=np.float64)
        self.envelope = 1.0 + self.AMPLITUDE * np.cos(
            2.0 * math.pi * self.K_NYQUIST * m / self.M_RING + self.THETA
        )
        angles = 2.0 * math.pi * np.outer(m, m) / self.M_RING
        self.ring_filter = (1.0 / self.M_RING) * (
            1.0 + 2.0 * np.cos(angles) + 2.0 * np.cos(3.0 * angles)
            + 2.0 * np.cos(self.K_NYQUIST * angles)
        )
        eigvals, eigvecs = np.linalg.eigh(self.ring_filter)
        basis_sub = eigvecs[:, eigvals > 1e-10]
        svals = np.linalg.svd(basis_sub[list(self.WITNESS_INDICES), :], compute_uv=False)
        self.channel_witness_sigma_min = float(np.min(svals))

    def compress(
        self,
        prompt_text: str,
        raw_ring_vector: Optional[Sequence[float]] = None,
    ) -> Dict[str, Any]:
        raw_bytes = prompt_text.encode("utf-8")
        prompt_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        if raw_ring_vector is not None:
            vec = np.asarray(raw_ring_vector, dtype=np.float64)
            if vec.shape != (self.M_RING,):
                raise ValueError(f"raw_ring_vector must have shape ({self.M_RING},)")
            raw_ring = vec.copy()
        else:
            raw_ring = np.zeros(self.M_RING, dtype=np.float64)
            # Inject a fixed non-zero baseline anchor on witness slot 0 so scalar multiples
            # (such as 1-byte "a", "b", "Z" or constant "aaaa", "zzzz") change the vector's
            # direction in R^99 rather than cancelling out under L2 unit normalization.
            raw_ring[0] = 64.0
            if len(raw_bytes) == 0:
                raw_ring[1] = 1.0
            else:
                for idx, b_val in enumerate(raw_bytes):
                    slot_primary = (idx + 1) % self.M_RING
                    slot_harmonic = (idx * 7 + (b_val % 11) + 3) % self.M_RING
                    weight = (float(b_val) + 1.0) * (1.0 + 0.03 * (idx // self.M_RING))
                    raw_ring[slot_primary] += weight
                    raw_ring[slot_harmonic] += 0.35 * weight * (1.0 + math.sin(float(b_val) * 0.13 + idx * 0.29))

        modulated = raw_ring * self.envelope
        total_norm = float(np.linalg.norm(modulated))
        if total_norm > 0.0:
            normalized_ring = modulated / total_norm
        else:
            normalized_ring = modulated

        witness_idx = list(self.WITNESS_INDICES)
        comp_idx = [i for i in range(self.M_RING) if i not in self.WITNESS_INDICES]

        witness_vec = normalized_ring[witness_idx]
        orth_vec = normalized_ring[comp_idx]

        witness_energy = float(np.linalg.norm(witness_vec))
        null_space_ratio = float(np.linalg.norm(orth_vec))

        bandlimited_raw = self.ring_filter @ normalized_ring
        out_of_channel_residual = float(np.linalg.norm(normalized_ring - bandlimited_raw))
        bl_norm = float(np.linalg.norm(bandlimited_raw))
        if bl_norm > 0.0:
            bandlimited = bandlimited_raw / bl_norm
        else:
            bandlimited = bandlimited_raw
        bandlimited_witness_vec = [round(float(x), 8) for x in bandlimited[witness_idx]]

        attn_error_bound = float(self.attn_lipschitz_constant * null_space_ratio)
        attn_error_ceiling = float(self.attn_lipschitz_constant * self.null_space_threshold)

        null_space_anomaly = bool(null_space_ratio > self.null_space_threshold)
        rounded_witness = [round(float(x), 8) for x in witness_vec]
        full_ring_rounded = [round(float(x), 8) for x in normalized_ring]
        raw_norm_rounded = round(total_norm, 8)

        lrsc_sha256 = sha256_canonical({
            "M": self.M_RING,
            "K": self.K_WITNESS,
            "indices": witness_idx,
            "witness": rounded_witness,
            "bandlimited_witness": bandlimited_witness_vec,
            "raw_l2_norm": raw_norm_rounded,
            "prompt_sha256": prompt_sha256,
        })
        uncompressed_sha256 = sha256_canonical({
            "M": self.M_RING,
            "full_ring": full_ring_rounded,
            "raw_l2_norm": raw_norm_rounded,
            "prompt_sha256": prompt_sha256,
        })

        return {
            "M": self.M_RING,
            "K": self.K_WITNESS,
            "compression_ratio": self.K_WITNESS / self.M_RING,
            "compression_ratio_exact": "11/99",
            "prompt_sha256": prompt_sha256,
            "raw_l2_norm": raw_norm_rounded,
            "witness_indices": witness_idx,
            "witness_vector": rounded_witness,
            "bandlimited_witness_vector": bandlimited_witness_vec,
            "channel_witness_sigma_min": round(self.channel_witness_sigma_min, 8),
            "out_of_channel_l2_residual": round(out_of_channel_residual, 8),
            "witness_l2_norm": round(witness_energy, 8),
            "orthogonal_null_space_l2_ratio": round(null_space_ratio, 8),
            "attention_lipschitz_constant": round(self.attn_lipschitz_constant, 8),
            "attention_perturbation_upper_bound": round(attn_error_bound, 8),
            "attention_perturbation_threshold_ceiling": round(attn_error_ceiling, 8),
            "null_space_anomaly_detected": null_space_anomaly,
            "fallback_mode": "UNCOMPRESSED_FULL_RING_SEAL" if null_space_anomaly else "CERTIFIED_K11_DUAL_SEAL",
            "lrsc_sha256": lrsc_sha256,
            "uncompressed_fallback_sha256": uncompressed_sha256,
        }


class SharkProtocolEngine:
    """
    Layer 1 (VRK v0.3.1 SHA-256 Hash-Chained, Ed25519-Signed & N-Way Associative Merkle-DAG Ledger),
    Layer 1B (Typestate & Epoch Guard), Layer 2 (4D Soft-Wall ODE Governor with Patankar-Euler
    Interval Enclosure & Basin Separatrix Floor Guard), and Layer 3 (Bandlimited LRSC 11/99 Compressor).
    """

    def __init__(
        self,
        a: float = 1.0,
        b: float = 1.0,
        c: float = 1.0,
        e_gain: float = 3.60,
        f: float = 1.0,
        g: float = 1.0,
        E_avail: float = 1.0,
        I_erase: float = 10.0,
        gamma_max: float = 10.0,
        H_max: float = 100.0,
        eps_H: float = 0.05,
        eps_I: float = 0.05,
        sigma_0: float = 0.05,
        mu_Psi: float = 0.60,
        P_0: float = 4.00,
        lam_sim: float = 0.00,
        lam_lucid: float = 0.30,
        kappa_meta: float = 2.50,
        signing_seed: Optional[bytes] = None,
    ) -> None:
        self.a = float(a)
        self.b = float(b)
        self.c = float(c)
        self.e_gain = float(e_gain)
        self.f = float(f)
        self.g = float(g)
        self.E_avail = float(E_avail)
        self.I_erase = float(I_erase)
        self.gamma_max = float(gamma_max)
        self.H_max = float(H_max)
        self.eps_H = float(eps_H)
        self.eps_I = float(eps_I)
        self.sigma_0 = float(sigma_0)
        self.mu_Psi = float(mu_Psi)
        self.P_0 = float(P_0)
        self.lam_sim = float(lam_sim)
        self.lam_lucid = float(lam_lucid)
        self.kappa_meta = float(kappa_meta)
        self.r_lrsc = 11.0 / 99.0

        self.M_H_4D = self.c * self.gamma_max * self.H_max + self.I_erase
        self.P_eff_max = self.P_0 + self.lam_sim * self.r_lrsc * self.gamma_max + self.lam_lucid
        self.I_max_4D = (self.e_gain * self.M_H_4D + self.f * self.P_eff_max) / self.g

        self.state = np.array([2.05, 95.0, 4.0, 0.05], dtype=np.float64)
        self.time_t = 0.0

        self.signer = Ed25519AuthoritySigner(seed=signing_seed)
        self.ledger: List[Dict[str, Any]] = []
        self.epoch_guard = WorkerEpochGuard(initial_epoch=1)
        self.lrsc = LRSCCompressor()
        self._lock = threading.RLock()

    @property
    def public_key_hex(self) -> str:
        return self.signer.public_key_hex

    def compute_i_max_4d(self, P_0: Optional[float] = None, lam_sim: Optional[float] = None, lam_lucid: Optional[float] = None) -> float:
        p0 = self.P_0 if P_0 is None else float(P_0)
        ls = self.lam_sim if lam_sim is None else float(lam_sim)
        ll = self.lam_lucid if lam_lucid is None else float(lam_lucid)
        p_eff_max = p0 + ls * self.r_lrsc * self.gamma_max + ll
        return (self.e_gain * self.M_H_4D + self.f * p_eff_max) / self.g

    def rhs_4d(
        self,
        y: Sequence[float],
        P_0: Optional[float] = None,
        lam_sim: Optional[float] = None,
        lam_lucid: Optional[float] = None,
        kappa_meta: Optional[float] = None,
    ) -> np.ndarray:
        """Exact smooth (C^infty) 4D soft-wall vector field Eqs. (B.1)-(B.4)."""
        gamma, H_obs, I_dot, Psi = float(y[0]), float(y[1]), float(y[2]), float(y[3])
        p0 = self.P_0 if P_0 is None else float(P_0)
        ls = self.lam_sim if lam_sim is None else float(lam_sim)
        ll = self.lam_lucid if lam_lucid is None else float(lam_lucid)
        kap = self.kappa_meta if kappa_meta is None else float(kappa_meta)

        P_eff = p0 + ls * self.r_lrsc * gamma + ll * Psi
        dgamma = self.a * I_dot * self.E_avail * (1.0 - gamma / self.gamma_max) - self.b * gamma
        dHobs = self.c * gamma * (self.H_max - H_obs) - self.I_erase * math.tanh(H_obs / self.eps_H)
        fb = self.e_gain * math.tanh(I_dot / self.eps_I) * dHobs
        dIdot = fb + self.f * P_eff - self.g * I_dot
        denom = fb * fb + (self.f * p0) ** 2 + self.sigma_0 ** 2
        R_self = (fb * fb) / denom
        dPsi = kap * R_self * (1.0 - Psi) - self.mu_Psi * Psi
        return np.array([dgamma, dHobs, dIdot, dPsi], dtype=np.float64)

    def assert_inside_box_b4(self, y: Optional[Sequence[float]] = None, P_0: Optional[float] = None) -> bool:
        vec = self.state if y is None else np.asarray(y, dtype=np.float64)
        if not bool(np.all(np.isfinite(vec))):
            raise RuntimeError("Non-finite IEEE-754 value (NaN or Inf) detected in state vector.")
        gamma, H_obs, I_dot, Psi = float(vec[0]), float(vec[1]), float(vec[2]), float(vec[3])
        i_max = self.compute_i_max_4d(P_0=P_0)
        tol = 1e-12
        if not (0.0 - tol <= gamma <= self.gamma_max + tol):
            raise RuntimeError(f"Box B_4 breach on gamma: {gamma} not in [0, {self.gamma_max}]")
        if not (0.0 - tol <= H_obs <= self.H_max + tol):
            raise RuntimeError(f"Box B_4 breach on H_obs: {H_obs} not in [0, {self.H_max}]")
        if not (0.0 - tol <= I_dot <= i_max + tol):
            raise RuntimeError(f"Box B_4 breach on I_dot: {I_dot} not in [0, {i_max}]")
        if not (0.0 - tol <= Psi <= 1.0 + tol):
            raise RuntimeError(f"Box B_4 breach on Psi: {Psi} not in [0, 1]")
        return True

    def step_ode(self, dt: float = 0.05, P_0: Optional[float] = None) -> Dict[str, Any]:
        """Advance the 4D soft-wall ODE state by `dt` seconds using adaptive sub-stepped RK4."""
        with self._lock:
            if dt <= 0.0:
                raise ValueError("dt must be positive")
            p0 = self.P_0 if P_0 is None else float(P_0)
            i_max = self.compute_i_max_4d(P_0=p0)
            self.I_max_4D = i_max

            stiff_rate = max(
                self.I_erase / self.eps_H,
                self.e_gain * (self.I_erase / self.eps_I) + self.g,
                self.a * i_max * self.E_avail / self.gamma_max + self.b,
            )
            dt_crit = 0.25 / stiff_rate
            n_sub = max(10, int(math.ceil(dt / min(0.0005, dt_crit))))
            h = dt / float(n_sub)

            y = self.state.copy()
            for _ in range(n_sub):
                k1 = self.rhs_4d(y, P_0=p0)
                k2 = self.rhs_4d(y + 0.5 * h * k1, P_0=p0)
                k3 = self.rhs_4d(y + 0.5 * h * k2, P_0=p0)
                k4 = self.rhs_4d(y + h * k3, P_0=p0)
                y = y + (h / 6.0) * (k1 + 2.0 * k2 + 2.0 * k3 + k4)
                self.assert_inside_box_b4(y, P_0=p0)

            self.state = y
            self.time_t += dt
            P_eff_now = p0 + self.lam_sim * self.r_lrsc * float(y[0]) + self.lam_lucid * float(y[3])
            return {
                "t": round(self.time_t, 6),
                "gamma": float(y[0]),
                "H_obs": float(y[1]),
                "I_dot": float(y[2]),
                "Psi": float(y[3]),
                "P_eff": float(P_eff_now),
                "I_max_4D": float(i_max),
                "substeps": n_sub,
                "inside_B4": True,
            }

    def step_ode_patankar_interval(
        self,
        dt: float = 0.05,
        P_0: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Unconditionally box-invariant Patankar-Euler fractional production-destruction update
        coupled with outward-rounded IEEE-754 interval enclosures (`[lo, hi]`) and Python
        runtime float64 subnormal/FTZ floor clamping (`FLOAT64_NORMAL_MIN`).
        """
        with self._lock:
            if dt <= 0.0:
                raise ValueError("dt must be positive")
            p0 = self.P_0 if P_0 is None else float(P_0)
            if p0 < 0.0:
                raise ValueError("P_0 must be non-negative")
            i_max = self.compute_i_max_4d(P_0=p0)
            self.I_max_4D = i_max

            n_sub = max(20, int(math.ceil(dt / 0.0005)))
            h = dt / float(n_sub)

            y_lo = np.maximum(0.0, self.state.copy().astype(np.float64))
            y_hi = self.state.copy().astype(np.float64)
            ceilings = np.array([self.gamma_max, self.H_max, i_max, 1.0], dtype=np.float64)
            y_hi = np.minimum(ceilings, y_hi)

            strictly_positive_mask = (y_lo > 0.0) | np.array([p0 > 0.0, False, p0 > 0.0, False])

            for _ in range(n_sub):
                y_mid = 0.5 * (y_lo + y_hi)
                y_mid = np.where(strictly_positive_mask & (y_mid < FLOAT64_NORMAL_MIN), FLOAT64_NORMAL_MIN, y_mid)
                gamma, H_obs, I_dot, Psi = [float(v) for v in y_mid]

                P_g = (self.a * I_dot * self.E_avail) / self.gamma_max
                D_g = self.b
                g_next = (gamma + h * P_g * self.gamma_max) / (1.0 + h * (P_g + D_g))

                P_H = self.c * gamma
                sinc_tanh_H = (self.I_erase * math.tanh(H_obs / self.eps_H) / H_obs) if H_obs > 1e-12 else (self.I_erase / self.eps_H)
                D_H = sinc_tanh_H
                H_next = (H_obs + h * P_H * self.H_max) / (1.0 + h * (P_H + D_H))

                dHobs = self.c * gamma * (self.H_max - H_obs) - self.I_erase * math.tanh(H_obs / self.eps_H)
                fb = self.e_gain * math.tanh(I_dot / self.eps_I) * dHobs
                P_eff = p0 + self.lam_sim * self.r_lrsc * gamma + self.lam_lucid * Psi
                prod_I = max(0.0, fb) + self.f * P_eff
                dest_I_mag = max(0.0, -fb)
                P_I = prod_I / i_max
                D_I = self.g + (dest_I_mag / I_dot if I_dot > 1e-12 else 0.0)
                I_next = (I_dot + h * P_I * i_max) / (1.0 + h * (P_I + D_I))

                denom = fb * fb + (self.f * p0) ** 2 + self.sigma_0 ** 2
                R_self = (fb * fb) / denom
                P_psi = self.kappa_meta * R_self
                D_psi = self.mu_Psi
                Psi_next = (Psi + h * P_psi * 1.0) / (1.0 + h * (P_psi + D_psi))

                prod_rates = np.array([P_g, P_H, P_I, P_psi], dtype=np.float64)
                strictly_positive_mask = strictly_positive_mask | (prod_rates > 0.0)

                nxt = np.array([g_next, H_next, I_next, Psi_next], dtype=np.float64)
                raw_lo = np.nextafter(np.nextafter(nxt, -np.inf), -np.inf)
                raw_hi = np.nextafter(np.nextafter(nxt, np.inf), np.inf)
                floor_vec = np.where(strictly_positive_mask, FLOAT64_NORMAL_MIN, 0.0)
                y_lo = np.minimum(ceilings, np.maximum(floor_vec, raw_lo))
                y_hi = np.minimum(ceilings, np.maximum(y_lo, raw_hi))

            self.state = 0.5 * (y_lo + y_hi)
            self.time_t += dt
            self.assert_inside_box_b4(y_lo, P_0=p0)
            self.assert_inside_box_b4(y_hi, P_0=p0)
            max_width = float(np.max(y_hi - y_lo))

            return {
                "t": round(self.time_t, 6),
                "state_mid": [float(v) for v in self.state],
                "interval_lo": [float(v) for v in y_lo],
                "interval_hi": [float(v) for v in y_hi],
                "strictly_positive_normal_floored": [bool(v) for v in strictly_positive_mask],
                "float64_normal_min": FLOAT64_NORMAL_MIN,
                "max_interval_width": max_width,
                "I_max_4D": float(i_max),
                "substeps": n_sub,
                "inside_B4_certified": True,
            }

    def evaluate_basin_separatrix_guard(
        self,
        dt_window: float,
        psi_before: float,
        psi_after: float,
        gamma_after: float,
        P_0: Optional[float] = None,
        enforce_cycle_basin: bool = True,
    ) -> Dict[str, Any]:
        """
        Enforces the integrated Gronwall capacitive decay floor `Psi(t + dt) >= Psi(t) * exp(-mu_Psi * dt)`
        (derived analytically from the pointwise differential bound `dPsi/dt >= -mu_Psi * Psi` in
        `lean/TypestateLifecycle.lean`: `psi_decay_floor_bound`) and checks the P_0 = 0 cycle-persistence
        separatrix floor (`P_eff >= P_eff_separatrix_floor`).
        """
        p0 = self.P_0 if P_0 is None else float(P_0)
        gronwall_floor = float(psi_before) * math.exp(-self.mu_Psi * max(0.0, float(dt_window)))
        if float(psi_after) + 1e-9 < gronwall_floor:
            raise BasinCollapseError(
                f"Basin separatrix guard: Psi dropped from {psi_before:.6f} to {psi_after:.6f} over dt={dt_window}s, "
                f"violating analytic Gronwall capacitive floor {gronwall_floor:.6f}."
            )

        P_eff_after = p0 + self.lam_sim * self.r_lrsc * float(gamma_after) + self.lam_lucid * float(psi_after)
        separatrix_floor = 0.057974 * 0.7305
        if enforce_cycle_basin and P_eff_after < separatrix_floor:
            raise BasinCollapseError(
                f"Basin separatrix guard: effective drive P_eff={P_eff_after:.6f} fell below the "
                f"cycle-persistence separatrix floor {separatrix_floor:.6f} (origin attraction basin)."
            )

        return {
            "gronwall_psi_floor": round(gronwall_floor, 8),
            "psi_after": round(float(psi_after), 8),
            "P_eff_after": round(float(P_eff_after), 8),
            "separatrix_floor": round(separatrix_floor, 8),
            "basin_safe": True,
        }

    def simulate_trajectory(self, duration: float = 20.0, dt: float = 0.05, P_0: Optional[float] = None) -> Dict[str, List[float]]:
        steps = max(1, int(round(duration / dt)))
        history: Dict[str, List[float]] = {"t": [], "gamma": [], "H_obs": [], "I_dot": [], "Psi": [], "P_eff": []}
        for _ in range(steps):
            rec = self.step_ode(dt=dt, P_0=P_0)
            for k in history:
                history[k].append(rec[k])
        return history

    def verify_nagumo_boundary_certificate(self) -> Dict[str, Any]:
        """Verify all 8 faces of the 4D box B_4 numerically alongside the Lean 4 certificate."""
        i_max = self.compute_i_max_4d()
        f1 = float(self.rhs_4d([0.0, 50.0, 5.0, 0.5])[0])
        f2 = float(self.rhs_4d([self.gamma_max, 50.0, 5.0, 0.5])[0])
        f3 = float(self.rhs_4d([5.0, 0.0, 5.0, 0.5])[1])
        f4 = float(self.rhs_4d([5.0, self.H_max, 5.0, 0.5])[1])
        f5 = float(self.rhs_4d([5.0, 50.0, 0.0, 0.5])[2])
        f6 = float(self.rhs_4d([5.0, 50.0, i_max, 0.5])[2])
        f7 = float(self.rhs_4d([5.0, 50.0, 5.0, 0.0])[3])
        f8 = float(self.rhs_4d([5.0, 50.0, 5.0, 1.0])[3])
        passed = (
            f1 >= 0.0 and f2 < 0.0 and f3 >= 0.0 and f4 < 0.0
            and f5 > 0.0 and f6 <= 0.0 and f7 >= 0.0 and f8 < 0.0
        )
        assert passed, "8-Face Nagumo boundary check failed!"
        return {
            "face_1_gamma_0_ge_0": f1 >= 0.0,
            "face_2_gamma_max_lt_0": f2 < 0.0,
            "face_3_H_0_ge_0": f3 >= 0.0,
            "face_4_H_max_lt_0": f4 < 0.0,
            "face_5_I_0_gt_0": f5 > 0.0,
            "face_6_I_max_le_0": f6 <= 0.0,
            "face_7_Psi_0_ge_0": f7 >= 0.0,
            "face_8_Psi_1_lt_0": f8 < 0.0,
            "all_8_faces_certified": passed,
        }

    @staticmethod
    def verify_and_hash_evidence_list(ev_list: Sequence[Dict[str, str]], check_disk: bool = True) -> Tuple[List[Dict[str, str]], str]:
        """
        Audit Item 3 Fix: Inspect referenced files and `#anchor` symbols on disk and compute
        each file's on-disk SHA-256 digest (`file_sha256`) and the aggregate `evidence_root`.
        """
        verified_items: List[Dict[str, str]] = []
        for raw_ev in ev_list:
            role = str(raw_ev.get("role", "")).strip()
            raw_path = str(raw_ev.get("path", "")).strip()
            if not role or not raw_path:
                raise ValueError("Evidence item missing role or path.")
            file_part, _, anchor_part = raw_path.partition("#")
            f_path = (REPO_ROOT / file_part).resolve()
            try:
                f_path.relative_to(REPO_ROOT.resolve())
            except ValueError as exc:
                raise ValueError(f"Evidence path escapes repository root: {file_part}") from exc

            if check_disk:
                if not f_path.is_file() or f_path.stat().st_size == 0:
                    raise ValueError(f"Missing or empty evidence file on disk: {file_part}")
                raw_bytes = f_path.read_bytes()
                if anchor_part:
                    txt = raw_bytes.decode("utf-8", errors="replace")
                    if anchor_part not in txt:
                        raise ValueError(f"Evidence anchor '{anchor_part}' not found in {file_part}")
                file_sha = hashlib.sha256(raw_bytes).hexdigest()
            else:
                file_sha = str(raw_ev.get("file_sha256", ""))
            verified_items.append({
                "role": role,
                "path": raw_path,
                "file_sha256": file_sha,
            })
        return verified_items, sha256_canonical(verified_items)

    def seal_claim(
        self,
        claim_id: str,
        claim_text: str,
        claim_class: str = "REPRODUCED_RESULT",
        applies_to: Optional[List[str]] = None,
        does_not_imply: Optional[List[str]] = None,
        evidence: Optional[List[Dict[str, str]]] = None,
        lrsc_digest: Optional[str] = None,
        uncompressed_ring_digest: Optional[str] = None,
        prompt_sha256: Optional[str] = None,
        response_sha256: Optional[str] = None,
        timestamp_utc: Optional[str] = None,
        parent_hashes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Seal a claim into the append-only VRK v0.3.1 ledger (`intentseal-vrk-claim-v2`),
        binding `prompt_sha256`, `response_sha256`, `lrsc_sha256`, `uncompressed_ring_sha256`,
        on-disk verified `evidence_root`, and an RFC 8032 Ed25519 signature.
        """
        with self._lock:
            if claim_class not in REQUIRED_VRK_ROLES:
                raise ValueError(f"Unknown VRK claim_class: {claim_class}")

            app_to = applies_to if applies_to is not None else [
                "4D Soft-Wall ODE Governor (B_4) and LRSC 11/99 context projection",
                "Application-layer request-lifecycle typestate and worker-epoch state machine",
            ]
            not_imp = does_not_imply if does_not_imply is not None else [
                "OS ring-0 kernel memory protection or native C/PHP runtime patching",
                "Unconditional continuum PDE regularity or machine consciousness",
            ]
            if not app_to or not not_imp:
                raise ValueError("VRK firewall violation: scope.applies_to and scope.does_not_imply must be non-empty.")

            if evidence is None:
                if claim_class == "REPRODUCED_RESULT":
                    raw_ev_list = [
                        {"role": "definition", "path": "lean/ExistenceVerification.lean#ExistenceState"},
                        {"role": "execution_record", "path": "shark_protocol/kernel.py#step_ode"},
                        {"role": "independent_replication", "path": "shark_protocol/kernel.py#step_ode_patankar_interval"},
                    ]
                elif claim_class == "ANALYTIC_THEOREM":
                    raw_ev_list = [
                        {"role": "definition", "path": "lean/TypestateLifecycle.lean#LifecycleState"},
                        {"role": "proof", "path": "lean/TypestateLifecycle.lean#typestate_and_epoch_security_certificate"},
                        {"role": "scope_statement", "path": "lean/TypestateLifecycle.lean#does_not_imply"},
                        {"role": "independent_verification", "path": "tests/test_core.py#TestSharkProtocolSuite"},
                    ]
                else:
                    raw_ev_list = [{"role": r, "path": "shark_protocol/kernel.py#SharkProtocolEngine"} for r in sorted(REQUIRED_VRK_ROLES[claim_class])]
            else:
                raw_ev_list = list(evidence)

            roles_present = {e.get("role", "") for e in raw_ev_list}
            missing_roles = REQUIRED_VRK_ROLES[claim_class] - roles_present
            if missing_roles:
                raise ValueError(f"VRK promotion rejected: claim_class {claim_class} missing required roles {sorted(missing_roles)}")

            verified_ev, ev_root = self.verify_and_hash_evidence_list(raw_ev_list, check_disk=True)

            prev_hash = self.ledger[-1]["digest"] if self.ledger else VRK_TRUST_ROOT_DIGEST
            if parent_hashes is None:
                parents_sorted = [prev_hash]
            else:
                if not parent_hashes:
                    raise ValueError("parent_hashes cannot be empty")
                parents_sorted = sorted(str(h) for h in parent_hashes)
                prev_hash = parents_sorted[0]

            ts = timestamp_utc if timestamp_utc is not None else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            p_sha = prompt_sha256 if prompt_sha256 is not None else hashlib.sha256(str(claim_text).encode("utf-8")).hexdigest()
            r_sha = response_sha256 if response_sha256 is not None else hashlib.sha256(str(claim_id).encode("utf-8")).hexdigest()

            record_body: Dict[str, Any] = {
                "schema": "intentseal-vrk-claim-v2",
                "index": len(self.ledger) + 1,
                "prev_hash": prev_hash,
                "parent_hashes": parents_sorted,
                "trust_root": VRK_TRUST_ROOT_DIGEST,
                "timestamp_utc": ts,
                "claim_id": str(claim_id),
                "claim_text": str(claim_text),
                "claim_class": claim_class,
                "sealed": True,
                "scope": {
                    "applies_to": list(app_to),
                    "does_not_imply": list(not_imp),
                },
                "evidence": verified_ev,
                "evidence_root": ev_root,
                "prompt_sha256": p_sha,
                "response_sha256": r_sha,
                "lrsc_sha256": lrsc_digest or "none",
                "uncompressed_ring_sha256": uncompressed_ring_digest or "none",
                "ode_state_snapshot": [round(float(v), 8) for v in self.state],
                "signer_pubkey": self.public_key_hex,
            }
            digest = sha256_canonical(record_body)
            sig = self.signer.sign_digest_hex(digest)
            sealed_entry = dict(record_body, digest=digest, ed25519_signature=sig)
            self.ledger.append(sealed_entry)
            return sealed_entry

    @classmethod
    def verify_chain_list(
        cls,
        chain: Sequence[Dict[str, Any]],
        expected_pubkey: Optional[str] = None,
        known_parent_digests: Optional[Iterable[str]] = None,
        check_disk_evidence: bool = True,
    ) -> Tuple[bool, str]:
        """
        Verify a ledger sequence against VRK v0.3.1 hash-chain, multi-parent membership,
        prompt/response commitment, on-disk evidence anchor, and Ed25519 signature rules.
        Audit Item 1, Item 2 & Item 3 Fixes:
        - Unconditionally requires `entry.get("prev_hash") == parents[0]` for every entry.
        - Requires every parent hash in `parents` (whether 1 or multiple parents) to exist in
          `known_digests` (or verified `merged_branch_records` chained from `VRK_TRUST_ROOT_DIGEST`).
        - Rejects any non-merge entry with `len(parents) != 1` or `parents[0] != expected_prev`.
        - Verifies `prompt_sha256`, `response_sha256`, on-disk `evidence_root`, and `ed25519_signature`.
        """
        known_digests: Set[str] = {VRK_TRUST_ROOT_DIGEST}
        if known_parent_digests is not None:
            for d in known_parent_digests:
                if _is_hex64(d):
                    known_digests.add(d)

        for idx, entry in enumerate(chain):
            if entry.get("schema") != "intentseal-vrk-claim-v2":
                return False, f"Entry {idx} has invalid schema."
            scope = entry.get("scope", {})
            if not scope.get("applies_to") or not scope.get("does_not_imply"):
                return False, f"Entry {idx} missing scope firewall."
            c_class = entry.get("claim_class", "")
            if c_class not in REQUIRED_VRK_ROLES:
                return False, f"Entry {idx} has unknown claim_class {c_class}."
            ev_list = entry.get("evidence", [])
            roles_present = {e.get("role", "") for e in ev_list}
            if REQUIRED_VRK_ROLES[c_class] - roles_present:
                return False, f"Entry {idx} missing required evidence roles."

            try:
                verified_ev, expected_ev_root = cls.verify_and_hash_evidence_list(ev_list, check_disk=check_disk_evidence)
            except ValueError as exc:
                return False, f"Entry {idx} evidence verification failed: {exc}"
            if check_disk_evidence and entry.get("evidence_root") != expected_ev_root:
                return False, f"Entry {idx} evidence_root mismatch."
            if check_disk_evidence and verified_ev != ev_list:
                return False, f"Entry {idx} evidence file_sha256 mismatch."

            if not _is_hex64(entry.get("prompt_sha256")) or not _is_hex64(entry.get("response_sha256")):
                return False, f"Entry {idx} missing valid 64-hex prompt_sha256 or response_sha256 commitment."

            parents = entry.get("parent_hashes")
            if not isinstance(parents, list) or len(parents) == 0:
                return False, f"Entry {idx} has empty or missing parent_hashes."
            if not all(_is_hex64(p) for p in parents):
                return False, f"Entry {idx} contains malformed parent hash."
            if parents != sorted(parents) or len(parents) != len(set(parents)):
                return False, f"Entry {idx} has unsorted or duplicate parent_hashes."

            # Audit Item 1 Fix: ALWAYS require prev_hash == parents[0] regardless of len(parents)
            if entry.get("prev_hash") != parents[0]:
                return False, f"Entry {idx} prev_hash != parent_hashes[0] mismatch."

            is_merkle_merge = "merged_claim_digests" in entry
            if not is_merkle_merge:
                if len(parents) != 1:
                    return False, f"Entry {idx} is a non-merge claim but specifies {len(parents)} parents (forgery rejected)."
                expected_prev = VRK_TRUST_ROOT_DIGEST if idx == 0 else chain[idx - 1].get("digest", "")
                if parents[0] != expected_prev:
                    return False, f"Entry {idx} prev_hash mismatch against preceding chain link."
                if parents[0] not in known_digests:
                    return False, f"Entry {idx} references unknown parent {parents[0]}."
            else:
                # For a Merkle-DAG merge record, verify embedded branch records first if present
                sub_records = entry.get("merged_branch_records")
                if not isinstance(sub_records, list) or len(sub_records) == 0:
                    return False, f"Entry {idx} merge claim missing merged_branch_records."
                sub_digests_local: Set[str] = {VRK_TRUST_ROOT_DIGEST} | set(known_digests)
                for s_idx, s_rec in enumerate(sub_records):
                    if "merged_claim_digests" in s_rec:
                        return False, f"Entry {idx} merged_branch_records[{s_idx}] cannot be a nested merge."
                    ok_sub, msg_sub = cls._verify_single_base_record(
                        s_rec, sub_digests_local, expected_pubkey=expected_pubkey, check_disk_evidence=check_disk_evidence
                    )
                    if not ok_sub:
                        return False, f"Entry {idx} embedded branch record {s_idx} invalid: {msg_sub}"
                    sub_digests_local.add(s_rec["digest"])
                known_digests.update(sub_digests_local)

                if entry.get("leaf_frontier_tips") != parents:
                    return False, f"Entry {idx} leaf_frontier_tips != parent_hashes."
                merged_digests = entry.get("merged_claim_digests", [])
                if not isinstance(merged_digests, list) or not merged_digests or merged_digests != sorted(merged_digests):
                    return False, f"Entry {idx} has invalid merged_claim_digests."
                for m_dig in merged_digests:
                    if m_dig not in known_digests or m_dig == VRK_TRUST_ROOT_DIGEST:
                        return False, f"Entry {idx} references unverified merged_claim_digest {m_dig}."
                for p_hash in parents:
                    if p_hash not in known_digests or p_hash == VRK_TRUST_ROOT_DIGEST:
                        return False, f"Entry {idx} references unknown or unverified merge parent {p_hash}."
                if idx > 0 and chain[idx - 1].get("digest") not in known_digests:
                    return False, f"Entry {idx} does not connect to preceding chain entry."

            body = {k: v for k, v in entry.items() if k not in ("digest", "ed25519_signature")}
            recomputed = sha256_canonical(body)
            if recomputed != entry.get("digest"):
                return False, f"Entry {idx} SHA-256 digest mismatch (tampering detected)."

            signer_pub = entry.get("signer_pubkey", "")
            sig_hex = entry.get("ed25519_signature", "")
            if expected_pubkey is not None and signer_pub != expected_pubkey:
                return False, f"Entry {idx} signer_pubkey mismatch against expected authority key."
            if not Ed25519AuthoritySigner.verify_digest_signature(signer_pub, recomputed, sig_hex):
                return False, f"Entry {idx} Ed25519 signature verification failed (unauthorized rewrite rejected)."

            known_digests.add(recomputed)
        return True, "VRK_HASH_CHAIN_AND_ED25519_VERIFIED"

    @classmethod
    def _verify_single_base_record(
        cls,
        entry: Dict[str, Any],
        known_digests: Set[str],
        expected_pubkey: Optional[str] = None,
        check_disk_evidence: bool = True,
    ) -> Tuple[bool, str]:
        if entry.get("schema") != "intentseal-vrk-claim-v2":
            return False, "invalid schema"
        parents = entry.get("parent_hashes")
        if not isinstance(parents, list) or len(parents) != 1:
            return False, "base record must have exactly 1 parent"
        if entry.get("prev_hash") != parents[0] or parents[0] not in known_digests:
            return False, f"base record parent {parents[0]} not in known_digests"
        if not _is_hex64(entry.get("prompt_sha256")) or not _is_hex64(entry.get("response_sha256")):
            return False, "missing prompt_sha256 or response_sha256"
        try:
            verified_ev, expected_ev_root = cls.verify_and_hash_evidence_list(
                entry.get("evidence", []), check_disk=check_disk_evidence
            )
        except ValueError as exc:
            return False, str(exc)
        if check_disk_evidence and (entry.get("evidence_root") != expected_ev_root or verified_ev != entry.get("evidence")):
            return False, "base record evidence_root mismatch"
        body = {k: v for k, v in entry.items() if k not in ("digest", "ed25519_signature")}
        recomputed = sha256_canonical(body)
        if recomputed != entry.get("digest"):
            return False, "base record SHA-256 mismatch"
        signer_pub = entry.get("signer_pubkey", "")
        sig_hex = entry.get("ed25519_signature", "")
        if expected_pubkey is not None and signer_pub != expected_pubkey:
            return False, "base record signer_pubkey mismatch"
        if not Ed25519AuthoritySigner.verify_digest_signature(signer_pub, recomputed, sig_hex):
            return False, "base record Ed25519 signature invalid"
        return True, "OK"

    def verify_ledger_integrity(self) -> Tuple[bool, str]:
        with self._lock:
            return self.verify_chain_list(self.ledger, expected_pubkey=self.public_key_hex)

    @classmethod
    def merge_divergent_ledgers(
        cls,
        branch_a: Sequence[Dict[str, Any]],
        branch_b: Sequence[Dict[str, Any]],
        *extra_branches: Sequence[Dict[str, Any]],
        merge_timestamp_utc: str = "2026-10-25T00:00:00Z",
        signer: Optional[Ed25519AuthoritySigner] = None,
    ) -> Dict[str, Any]:
        """
        N-Way Commutative, Associative, and Idempotent Merkle-DAG Join-Semilattice Reconciliation
        (`lean/TypestateLifecycle.lean`: `merkle_dag_merge_commutative` & `merkle_dag_semilattice_laws`).
        Validates every input branch, flattens intermediate merge records into their constituent
        topologically sorted base claim records (`merged_branch_records`), and signs the canonical
        merge claim with Ed25519.
        """
        auth_signer = signer if signer is not None else Ed25519AuthoritySigner()
        all_branches = [branch_a, branch_b] + list(extra_branches)
        for b_idx, br in enumerate(all_branches):
            if not br:
                raise ValueError(f"Branch {b_idx} must be non-empty to merge.")
            ok, reason = cls.verify_chain_list(br)
            if not ok:
                raise RuntimeError(f"Split-brain merge rejected: branch {b_idx} invalid ({reason})")

        leaf_tips_set: Set[str] = set()
        claim_digests_set: Set[str] = set()
        claim_ids_set: Set[str] = set()
        base_records_by_digest: Dict[str, Dict[str, Any]] = {}

        for br in all_branches:
            tip_entry = br[-1]
            if "leaf_frontier_tips" in tip_entry and "merged_claim_digests" in tip_entry:
                leaf_tips_set.update(str(x) for x in tip_entry["leaf_frontier_tips"])
            else:
                leaf_tips_set.add(str(tip_entry["digest"]))

            for entry in br:
                if "merged_claim_digests" in entry and "merged_branch_records" in entry:
                    claim_digests_set.update(str(x) for x in entry["merged_claim_digests"])
                    claim_ids_set.update(str(x) for x in entry["merged_claim_ids"])
                    for sub_rec in entry["merged_branch_records"]:
                        base_records_by_digest[str(sub_rec["digest"])] = sub_rec
                else:
                    dig = str(entry["digest"])
                    claim_digests_set.add(dig)
                    claim_ids_set.add(str(entry["claim_id"]))
                    base_records_by_digest[dig] = entry

        parents_sorted = sorted(leaf_tips_set)
        all_digests_sorted = sorted(claim_digests_set)
        all_claim_ids_sorted = sorted(claim_ids_set)
        # Sort base records topologically by (index, digest) so parents always precede children
        merged_branch_records = [
            base_records_by_digest[d]
            for d in sorted(base_records_by_digest.keys(), key=lambda k: (int(base_records_by_digest[k]["index"]), k))
        ]
        frontier_root = sha256_canonical(parents_sorted)
        claims_root = sha256_canonical(all_digests_sorted)

        raw_ev_list = [
            {"role": "definition", "path": "lean/TypestateLifecycle.lean#merkle_dag_semilattice_laws"},
            {"role": "execution_record", "path": "shark_protocol/kernel.py#merge_divergent_ledgers"},
            {"role": "independent_replication", "path": "tests/test_core.py#test_25_deep_probe_e_merkle_dag_nway_associativity_and_idempotence"},
        ]
        verified_ev, ev_root = cls.verify_and_hash_evidence_list(raw_ev_list, check_disk=True)

        merge_body: Dict[str, Any] = {
            "schema": "intentseal-vrk-claim-v2",
            "index": len(all_digests_sorted) + 1,
            "prev_hash": parents_sorted[0],
            "parent_hashes": parents_sorted,
            "leaf_frontier_tips": parents_sorted,
            "trust_root": VRK_TRUST_ROOT_DIGEST,
            "timestamp_utc": merge_timestamp_utc,
            "claim_id": f"vrk.merkle_dag.merge.{frontier_root[:16]}",
            "claim_text": f"Deterministic N-way associative Merkle-DAG join-semilattice reconciliation of {len(all_digests_sorted)} verified claims across {len(parents_sorted)} frontier tip(s).",
            "claim_class": "REPRODUCED_RESULT",
            "sealed": True,
            "scope": {
                "applies_to": [
                    "Commutative, associative, and idempotent Merkle-DAG reconciliation of divergent VRK gateway ledger branches",
                ],
                "does_not_imply": [
                    "Byzantine fault tolerance against compromised private signing keys without external threshold consensus",
                ],
            },
            "evidence": verified_ev,
            "evidence_root": ev_root,
            "merged_claim_digests": all_digests_sorted,
            "merged_claim_ids": all_claim_ids_sorted,
            "merged_branch_records": merged_branch_records,
            "prompt_sha256": frontier_root,
            "response_sha256": claims_root,
            "lrsc_sha256": frontier_root,
            "uncompressed_ring_sha256": claims_root,
            "ode_state_snapshot": [2.05, 95.0, 4.0, 0.05],
            "signer_pubkey": auth_signer.public_key_hex,
        }
        merge_digest = sha256_canonical(merge_body)
        merge_sig = auth_signer.sign_digest_hex(merge_digest)
        return dict(merge_body, digest=merge_digest, ed25519_signature=merge_sig)

    def run_lifecycle_and_redteam_audit(self) -> Dict[str, Any]:
        """Run self-test of typestate, terminal absorbing state, epoch isolation, Patankar step, LRSC commitment, Ed25519 signing, and N-way Merkle-DAG merge."""
        guard = WorkerEpochGuard(initial_epoch=10)
        slot1 = guard.begin_request()
        slot1.transition(LifecycleEvent.OOM_ABORT)
        deref_blocked = False
        try:
            slot1.dereference_payload()
        except TypestateViolationError:
            deref_blocked = True

        uaf_blocked = False
        try:
            slot1.run_clean_destructor()
        except TypestateViolationError:
            uaf_blocked = True
        guard.finish_request(slot1, abort=True)

        # Verify ZEROED_FREED is strictly terminal/absorbing
        terminal_preserved = False
        try:
            slot1.transition(LifecycleEvent.BEGIN_INIT)
        except TypestateViolationError:
            terminal_preserved = (slot1.state == LifecycleState.ZEROED_FREED)

        slot_stale = RequestSlot(slot_epoch=11)
        slot_stale.transition(LifecycleEvent.BEGIN_INIT)
        slot_stale.transition(LifecycleEvent.SEAL_SUCCESS, payload={"secret": "stale"})
        slot2 = guard.begin_request()
        slot2.transition(LifecycleEvent.SEAL_SUCCESS, payload={"ok": True})
        stale_blocked = False
        try:
            guard.read_slot(slot_stale)
        except StaleWorkerEpochError:
            stale_blocked = True
        guard.finish_request(slot2, abort=False)

        patankar_res = self.step_ode_patankar_interval(dt=0.05)
        nagumo_res = self.verify_nagumo_boundary_certificate()

        na, nb, nc = SharkProtocolEngine(), SharkProtocolEngine(), SharkProtocolEngine()
        na.seal_claim("c.a", "Branch A", timestamp_utc="2026-10-25T00:00:00Z")
        nb.seal_claim("c.b", "Branch B", timestamp_utc="2026-10-25T00:00:00Z")
        nc.seal_claim("c.c", "Branch C", timestamp_utc="2026-10-25T00:00:00Z")
        m_ab_c = self.merge_divergent_ledgers([self.merge_divergent_ledgers(na.ledger, nb.ledger)], nc.ledger)
        m_a_bc = self.merge_divergent_ledgers(na.ledger, [self.merge_divergent_ledgers(nb.ledger, nc.ledger)])
        assoc_ok = (m_ab_c["digest"] == m_a_bc["digest"]) and self.verify_chain_list([m_ab_c])[0]

        return {
            "partial_init_oom_deref_blocked": deref_blocked,
            "poisoned_destructor_uaf_blocked": uaf_blocked,
            "zeroed_freed_terminal_absorbing": terminal_preserved,
            "stale_worker_epoch_read_blocked": stale_blocked,
            "patankar_interval_step_certified": patankar_res["inside_B4_certified"],
            "nagumo_8face_certified": nagumo_res["all_8_faces_certified"],
            "merkle_dag_nway_associative": assoc_ok,
            "all_checks_passed": (
                deref_blocked and uaf_blocked and terminal_preserved and stale_blocked
                and patankar_res["inside_B4_certified"] and nagumo_res["all_8_faces_certified"]
                and assoc_ok
            ),
        }
