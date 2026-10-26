"""
Layer 4: Fail-Closed Multi-Cloud Execution Gateway & Loopback HTTP Proxy (`shark_protocol/gateway.py`)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Version: 1.3.2 (Concept DOI: 10.5281/zenodo.23618032)

Gateway Security & Verification Controls:
1. Strict Fail-Closed Provider Dispatch:
   - Silent cross-provider fallback is disabled by default (`allow_failover=False`).
   - If a live API key is configured for the target provider (or `require_live_dispatch=True`) and
     the external HTTP call fails, `process_request` aborts the request slot (`ABORTED_POISONED` ->
     `ZEROED_FREED`) and raises `GatewayDispatchError` fail-closed.
   - Offline simulation (`VRK_OFFLINE_SEALED_SIMULATION`) runs only when no live API key is configured
     and `require_live_dispatch=False`, cross-checking both `step_ode` (RK4) and
     `step_ode_patankar_interval` (Patankar-Euler) before sealing.
2. Token Registry Authentication (`sha256(token) -> tenant_id`), Per-Tenant Ledger Persistence & Non-Evicting Cap:
   - Authenticates Bearer tokens via a constant-time token registry mapping `sha256(token)` (64-hex)
     to a validated `tenant_id` (`^[A-Za-z0-9_.-]{1,64}$`), rejecting any unknown or unauthenticated
     Bearer token with HTTP `401 Unauthorized` (`GatewayAuthError`).
   - Persists every tenant's ledger to `<ledger_dir>/<tenant_id>.jsonl` with `os.fsync` and reloads
     persisted records on startup.
   - Enforces a hard capacity limit (`max_tenants=128`) without evicting active tenant ledgers:
     when `len(_tenant_engines) >= max_tenants`, requests for a new tenant raise `GatewayCapacityError`
     and return HTTP `503 Service Unavailable`.
   - Enforces a per-tenant sliding-window rate limit (`rate_limit_per_window=120` per `60.0s`, HTTP `429`).
3. Header-Only API Key Transmission:
   - Sends the Google Gemini API key via the `x-goog-api-key` HTTP header, never in the URL query string.
4. Hardened `ThreadingHTTPServer`:
   - Sets a per-connection socket timeout (`SOCKET_TIMEOUT_SECONDS = 10.0`) on `GatewayHTTPHandler`
     so slow clients cannot hold server threads.
   - Enforces `MAX_HTTP_CONTENT_LENGTH = 65536` (returning HTTP `413 Payload Too Large`).
   - Refuses non-loopback bind hosts unless `allow_remote=True` AND a non-empty token registry or
     `auth_token` (`SHARK_GATEWAY_BEARER_TOKEN`) is configured.
   - Reads `__version__`, `__doi__`, and `__concept_doi__` dynamically from `shark_protocol`.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

import requests
try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    def load_dotenv(*_args, **_kwargs):
        return False

from . import __concept_doi__, __doi__, __version__
from .kernel import (
    LifecycleEvent,
    SharkProtocolEngine,
    TypestateViolationError,
    _is_hex64,
)

load_dotenv()

TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
MAX_HTTP_CONTENT_LENGTH = 65536
SOCKET_TIMEOUT_SECONDS = 10.0


class GatewayConfigError(ValueError):
    """Raised when an invalid provider, tenant_id, or unsafe HTTP bind configuration is requested."""


class GatewayAuthError(PermissionError):
    """Raised when a missing or unknown Bearer token is presented (maps to HTTP 401)."""


class GatewayRateLimitError(GatewayConfigError):
    """Raised when a tenant exceeds its configured sliding-window request rate limit (maps to HTTP 429)."""


class GatewayCapacityError(RuntimeError):
    """Raised when max_tenants is reached so existing tenant ledgers are never evicted (maps to HTTP 503)."""


class GatewayDispatchError(RuntimeError):
    """Raised fail-closed when a live external cloud provider dispatch fails."""


SUPPORTED_PROVIDERS: Dict[str, Dict[str, str]] = {
    "groq": {
        "env_key": "GROQ_API_KEY",
        "model": "llama-3.3-70b-versatile",
        "url": "https://api.groq.com/openai/v1/chat/completions",
    },
    "together": {
        "env_key": "TOGETHER_API_KEY",
        "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "url": "https://api.together.ai/v1/chat/completions",
    },
    "gemini": {
        "env_key": "GEMINI_API_KEY",
        "model": "gemini-1.5-flash",
        "url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
    },
    "huggingface": {
        "env_key": "HUGGINGFACE_API_KEY",
        "model": "mistralai/Mistral-7B-Instruct-v0.2",
        "url": "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2",
    },
}


class MultiProviderGateway:
    """
    Four-layer execution gateway binding every request to:
      1. Layer 1B: Thread-safe `WorkerEpochGuard` + `RequestSlot` typestate lifecycle
      2. Layer 2 : Per-tenant isolated 4D Soft-Wall ODE dual-solver step with waking
                   basal drive floor (`min_waking_p0 >= 1.0 >> P_crit = 10/99`)
      3. Layer 3 : Bandlimited LRSC 11/99 spectral compression (`LRSCCompressor` with prompt commitment)
      4. Layer 1 : Append-only Ed25519-signed `intentseal-vrk-claim-v2` SHA-256 ledger seal persisted
                   per-tenant to `<ledger_dir>/<tenant_id>.jsonl` with `os.fsync`
    """

    def __init__(
        self,
        engine: Optional[SharkProtocolEngine] = None,
        min_waking_p0: float = 1.0,
        max_tenants: int = 128,
        signing_seed: Optional[bytes] = None,
        rate_limit_per_window: int = 120,
        rate_limit_window_sec: float = 60.0,
        token_registry: Optional[Dict[str, str]] = None,
        ledger_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        if min_waking_p0 < 10.0 / 99.0:
            raise ValueError("min_waking_p0 must be >= P_crit = 10/99 to guarantee waking basin persistence.")
        if max_tenants < 1:
            raise ValueError("max_tenants must be >= 1")
        if rate_limit_per_window < 1 or rate_limit_window_sec <= 0.0:
            raise ValueError("rate_limit_per_window must be >= 1 and rate_limit_window_sec > 0.")

        self.min_waking_p0 = float(min_waking_p0)
        self.max_tenants = int(max_tenants)
        self.rate_limit_per_window = int(rate_limit_per_window)
        self.rate_limit_window_sec = float(rate_limit_window_sec)

        if ledger_dir is not None:
            self.ledger_dir = Path(ledger_dir)
            self.ledger_dir.mkdir(parents=True, exist_ok=True)
        else:
            env_ldir = os.environ.get("SHARK_LEDGER_DIR", "").strip()
            if env_ldir:
                self.ledger_dir = Path(env_ldir)
                self.ledger_dir.mkdir(parents=True, exist_ok=True)
            else:
                self.ledger_dir = Path(tempfile.mkdtemp(prefix="shark_tenant_ledgers_"))

        default_ledger_path = self.ledger_dir / "default.jsonl"
        if engine is not None:
            self.engine = engine
            if self.engine.ledger_path is None:
                self.engine.ledger_path = default_ledger_path
        else:
            self.engine = SharkProtocolEngine(signing_seed=signing_seed, ledger_path=default_ledger_path)

        self._gateway_lock = threading.RLock()
        self._tenant_engines: "collections.OrderedDict[str, SharkProtocolEngine]" = collections.OrderedDict()
        self._tenant_engines["default"] = self.engine
        self._tenant_windows: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)

        # Token registry maps 64-hex sha256(token) -> validated tenant_id
        self._token_registry: Dict[str, str] = {}
        env_reg_json = os.environ.get("SHARK_GATEWAY_TOKEN_REGISTRY_JSON", "").strip()
        if env_reg_json:
            parsed_env = json.loads(env_reg_json)
            if isinstance(parsed_env, dict):
                for k, v in parsed_env.items():
                    self._add_registry_entry(str(k), str(v))
        if token_registry is not None:
            for k, v in token_registry.items():
                self._add_registry_entry(str(k), str(v))

    @staticmethod
    def hash_bearer_token(bearer_token: str) -> str:
        """Compute canonical 64-hex SHA-256 digest of a raw Bearer token for registry lookup."""
        if not isinstance(bearer_token, str) or not bearer_token.strip():
            raise ValueError("Bearer token must be a non-empty string.")
        return hashlib.sha256(bearer_token.strip().encode("utf-8")).hexdigest()

    @staticmethod
    def derive_tenant_from_token(bearer_token: str) -> str:
        """Deterministic tenant identifier derived from a Bearer token."""
        digest = hashlib.sha256(b"shark_tenant_token_binding_v1:" + bearer_token.encode("utf-8")).hexdigest()
        return f"t_{digest[:16]}"

    def _add_registry_entry(self, key_or_hash: str, tenant_id: str) -> str:
        norm_tenant = tenant_id.strip()
        if not TENANT_ID_PATTERN.match(norm_tenant):
            raise GatewayConfigError(f"Invalid tenant_id '{tenant_id}' in token registry.")
        k = key_or_hash.strip()
        token_sha = k.lower() if _is_hex64(k.lower()) else self.hash_bearer_token(k)
        with self._gateway_lock:
            self._token_registry[token_sha] = norm_tenant
        return token_sha

    def register_tenant_token(self, raw_token: str, tenant_id: str) -> str:
        """Register `sha256(raw_token) -> tenant_id` in the gateway token registry and return the 64-hex token hash."""
        if not isinstance(raw_token, str) or not raw_token.strip():
            raise GatewayConfigError("raw_token must be a non-empty string.")
        token_sha = self.hash_bearer_token(raw_token)
        return self._add_registry_entry(token_sha, tenant_id)

    @property
    def has_registered_tokens(self) -> bool:
        with self._gateway_lock:
            return len(self._token_registry) > 0

    def authenticate_bearer_token(self, raw_token: Optional[str]) -> str:
        """
        Authenticate `raw_token` against `_token_registry` (`sha256(token) -> tenant_id`) using
        constant-time comparison (`hmac.compare_digest`). Raises `GatewayAuthError` (HTTP 401)
        if `raw_token` is missing or unknown.
        """
        if not raw_token or not isinstance(raw_token, str) or not raw_token.strip():
            raise GatewayAuthError("Unauthorized: missing Bearer token.")
        cand_sha = self.hash_bearer_token(raw_token)
        matched_tenant: Optional[str] = None
        with self._gateway_lock:
            for reg_sha, reg_tenant in self._token_registry.items():
                if hmac.compare_digest(cand_sha.encode("ascii"), reg_sha.encode("ascii")):
                    matched_tenant = reg_tenant
        if matched_tenant is None:
            raise GatewayAuthError("Unauthorized: unknown or invalid Bearer token.")
        return matched_tenant

    def _check_rate_limit(self, norm_tenant_id: str) -> None:
        now = time.monotonic()
        with self._gateway_lock:
            dq = self._tenant_windows[norm_tenant_id]
            cutoff = now - self.rate_limit_window_sec
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= self.rate_limit_per_window:
                raise GatewayRateLimitError(
                    f"Rate limit exceeded for tenant '{norm_tenant_id}': max {self.rate_limit_per_window} "
                    f"requests per {self.rate_limit_window_sec:.1f}s window."
                )
            dq.append(now)

    def get_tenant_engine(self, tenant_id: str = "default") -> SharkProtocolEngine:
        """
        Return a persistent, isolated `SharkProtocolEngine` for `tenant_id`.
        Never evicts active tenant ledgers: if `len(_tenant_engines) >= max_tenants` when a
        new tenant is requested, raises `GatewayCapacityError` (HTTP 503).
        """
        norm_id = (tenant_id or "default").strip() or "default"
        if not TENANT_ID_PATTERN.match(norm_id):
            raise GatewayConfigError(
                f"Invalid tenant_id '{tenant_id}': must match ^[A-Za-z0-9_.-]{{1,64}}$."
            )
        with self._gateway_lock:
            if norm_id in self._tenant_engines:
                return self._tenant_engines[norm_id]

            if len(self._tenant_engines) >= self.max_tenants:
                raise GatewayCapacityError(
                    f"Tenant capacity reached (max_tenants={self.max_tenants}); refusing to evict active tenant ledgers."
                )

            tenant_ledger_path = self.ledger_dir / f"{norm_id}.jsonl"
            new_eng = SharkProtocolEngine(
                a=self.engine.a,
                b=self.engine.b,
                c=self.engine.c,
                e_gain=self.engine.e_gain,
                f=self.engine.f,
                g=self.engine.g,
                E_avail=self.engine.E_avail,
                I_erase=self.engine.I_erase,
                gamma_max=self.engine.gamma_max,
                H_max=self.engine.H_max,
                eps_H=self.engine.eps_H,
                eps_I=self.engine.eps_I,
                sigma_0=self.engine.sigma_0,
                mu_Psi=self.engine.mu_Psi,
                P_0=self.engine.P_0,
                lam_sim=self.engine.lam_sim,
                lam_lucid=self.engine.lam_lucid,
                kappa_meta=self.engine.kappa_meta,
                signer=self.engine.signer if getattr(self.engine.signer, "_seed", None) is None else None,
                signing_seed=getattr(self.engine.signer, "_seed", None),
                ledger_path=tenant_ledger_path,
            )
            self._tenant_engines[norm_id] = new_eng
            return new_eng

    @staticmethod
    def _has_usable_key(env_var: str) -> Optional[str]:
        val = os.environ.get(env_var, "").strip()
        if not val or val.startswith("your_") or val.endswith("_here"):
            return None
        return val

    def _dispatch_external_provider(self, provider: str, prompt: str, api_key: str) -> str:
        spec = SUPPORTED_PROVIDERS[provider]
        if provider in ("groq", "together"):
            resp = requests.post(
                spec["url"],
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": spec["model"], "messages": [{"role": "user", "content": prompt}], "max_tokens": 256},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data["choices"][0]["message"]["content"])
        if provider == "gemini":
            resp = requests.post(
                spec["url"],
                headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data["candidates"][0]["content"]["parts"][0]["text"])
        if provider == "huggingface":
            resp = requests.post(
                spec["url"],
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"inputs": prompt},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list) and data:
                return str(data[0].get("generated_text", ""))
            return str(data)
        raise GatewayConfigError(f"Unsupported provider: {provider}")

    def process_request(
        self,
        prompt: str,
        provider: str = "groq",
        simulate_oom_abort: bool = False,
        tenant_id: str = "default",
        requested_p0: Optional[float] = None,
        allow_failover: bool = False,
        require_live_dispatch: bool = False,
    ) -> Dict[str, Any]:
        provider_norm = provider.strip().lower()
        if provider_norm not in SUPPORTED_PROVIDERS:
            raise GatewayConfigError(
                f"Fail-closed gateway error: unknown provider '{provider}'. "
                f"Supported providers: {sorted(SUPPORTED_PROVIDERS.keys())}."
            )

        target_engine = self.get_tenant_engine(tenant_id)
        norm_id = (tenant_id or "default").strip() or "default"
        self._check_rate_limit(norm_id)

        raw_p0 = (1.0 + min(5.0, len(prompt) / 80.0)) if requested_p0 is None else float(requested_p0)
        effective_p0 = max(self.min_waking_p0, min(6.0, raw_p0))

        slot = target_engine.epoch_guard.begin_request()
        try:
            if simulate_oom_abort:
                slot.transition(LifecycleEvent.OOM_ABORT)
                raise TypestateViolationError("Simulated OOM abort during PARTIAL_INIT; request slot poisoned.")

            psi_before = float(target_engine.state[3])
            ode_snapshot = target_engine.step_ode(dt=0.025, P_0=effective_p0)
            patankar_snapshot = target_engine.step_ode_patankar_interval(dt=0.025, P_0=effective_p0)
            ode_snapshot["patankar_checked"] = patankar_snapshot["inside_B4_checked"]
            separatrix_check = target_engine.evaluate_basin_separatrix_guard(
                dt_window=0.05,
                psi_before=psi_before,
                psi_after=float(target_engine.state[3]),
                gamma_after=float(target_engine.state[0]),
                P_0=effective_p0,
                enforce_cycle_basin=True,
            )
            lrsc_bundle = target_engine.lrsc.compress(prompt)

            slot.transition(
                LifecycleEvent.SEAL_SUCCESS,
                payload={
                    "prompt": prompt,
                    "prompt_sha256": lrsc_bundle["prompt_sha256"],
                    "provider": provider_norm,
                    "tenant_id": norm_id,
                    "lrsc_sha256": lrsc_bundle["lrsc_sha256"],
                    "uncompressed_fallback_sha256": lrsc_bundle["uncompressed_fallback_sha256"],
                    "ode_snapshot": ode_snapshot,
                },
            )
            verified_payload = target_engine.epoch_guard.read_slot(slot)

            candidate_order: List[str] = [provider_norm]
            if allow_failover:
                candidate_order.extend(
                    p for p in ("groq", "together", "gemini", "huggingface") if p != provider_norm
                )

            configured_candidates = [
                (cand, self._has_usable_key(SUPPORTED_PROVIDERS[cand]["env_key"]))
                for cand in candidate_order
            ]
            usable_candidates = [(cand, key) for cand, key in configured_candidates if key is not None]

            if usable_candidates:
                last_err: Optional[Exception] = None
                response_text = ""
                used_provider = provider_norm
                dispatch_mode = "LIVE_API_DISPATCH"
                succeeded = False
                for cand, key in usable_candidates:
                    try:
                        response_text = self._dispatch_external_provider(cand, verified_payload["prompt"], key)
                        used_provider = cand
                        succeeded = True
                        break
                    except Exception as exc:
                        last_err = exc
                        if not allow_failover:
                            break
                if not succeeded:
                    raise GatewayDispatchError(
                        f"Fail-closed gateway error: live dispatch failed for provider '{provider_norm}' "
                        f"(allow_failover={allow_failover}): {type(last_err).__name__}"
                    ) from last_err
            else:
                if require_live_dispatch:
                    raise GatewayDispatchError(
                        f"Fail-closed gateway error: require_live_dispatch=True but no usable API key "
                        f"is configured for provider '{provider_norm}'."
                    )
                dispatch_mode = "VRK_OFFLINE_SEALED_SIMULATION"
                used_provider = provider_norm
                response_text = (
                    f"[VRK_OFFLINE_SEALED_SIMULATION] Verified 4-layer execution for provider='{provider_norm}' "
                    f"(LRSC={lrsc_bundle['compression_ratio_exact']}, prompt_sha256={lrsc_bundle['prompt_sha256'][:12]}..., "
                    f"lrsc_sha256={lrsc_bundle['lrsc_sha256'][:12]}...)."
                )

            prompt_sha256 = lrsc_bundle["prompt_sha256"]
            response_sha256 = hashlib.sha256(response_text.encode("utf-8")).hexdigest()

            vrk_entry = target_engine.seal_claim(
                claim_id=f"gateway.exec.{norm_id}.epoch_{slot.slot_epoch}",
                claim_text=f"4-layer verified gateway execution (mode={dispatch_mode}, provider={used_provider}, tenant={norm_id}).",
                claim_class="REPRODUCED_RESULT",
                lrsc_digest=lrsc_bundle["lrsc_sha256"],
                uncompressed_ring_digest=lrsc_bundle["uncompressed_fallback_sha256"],
                prompt_sha256=prompt_sha256,
                response_sha256=response_sha256,
            )
            target_engine.epoch_guard.finish_request(slot, abort=False)

            return {
                "status": "SEALED_OK",
                "dispatch_mode": dispatch_mode,
                "provider": used_provider,
                "tenant_id": norm_id,
                "effective_p0": effective_p0,
                "prompt_sha256": prompt_sha256,
                "response_sha256": response_sha256,
                "separatrix_guard": separatrix_check,
                "worker_epoch": slot.slot_epoch,
                "slot_final_state": slot.state.value,
                "slot_fence_seq": slot.fence_seq,
                "ode_state": ode_snapshot,
                "lrsc": lrsc_bundle,
                "vrk_seal": vrk_entry,
                "response": response_text,
            }
        except BaseException:
            target_engine.epoch_guard.finish_request(slot, abort=True)
            raise


def create_gateway_http_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    gateway: Optional[MultiProviderGateway] = None,
    allow_remote: bool = False,
    auth_token: Optional[str] = None,
    token_registry: Optional[Dict[str, str]] = None,
    max_content_length: int = MAX_HTTP_CONTENT_LENGTH,
    socket_timeout: float = SOCKET_TIMEOUT_SECONDS,
) -> Tuple[ThreadingHTTPServer, MultiProviderGateway]:
    norm_host = host.strip()
    env_token = os.environ.get("SHARK_GATEWAY_BEARER_TOKEN", "").strip()
    if env_token.startswith("your_") or env_token.endswith("_here"):
        env_token = ""
    effective_token = (auth_token if auth_token is not None else env_token).strip()

    gw = gateway if gateway is not None else MultiProviderGateway(token_registry=token_registry)
    if token_registry is not None and gateway is not None:
        for k, v in token_registry.items():
            gw._add_registry_entry(str(k), str(v))
    if effective_token:
        gw.register_tenant_token(effective_token, "default")

    if norm_host not in LOOPBACK_HOSTS:
        if not allow_remote or not gw.has_registered_tokens:
            raise GatewayConfigError(
                f"Refusing to bind HTTP gateway to non-loopback host '{norm_host}' without both "
                f"allow_remote=True and at least one registered Bearer token."
            )

    class GatewayHTTPHandler(BaseHTTPRequestHandler):
        timeout = float(socket_timeout)

        def setup(self) -> None:
            super().setup()
            if self.request is not None:
                self.request.settimeout(self.timeout)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _extract_bearer_token(self) -> Optional[str]:
            hdr = self.headers.get("Authorization", "")
            if hdr.startswith("Bearer "):
                return hdr[len("Bearer "):].strip()
            return None

        def _authenticate_request(self) -> Optional[str]:
            """
            Authenticate the HTTP request against `gw._token_registry`:
            - If `gw.has_registered_tokens` is True, a valid registered Bearer token is mandatory
              and maps deterministically to its registered `tenant_id`.
            - If `gw.has_registered_tokens` is False (local loopback dev mode), any request that
              supplies an unknown `Authorization` header is still rejected with HTTP 401 so a
              caller can never invent arbitrary tokens to pick tenants or evade rate limits.
            """
            raw_hdr = self.headers.get("Authorization")
            tok = self._extract_bearer_token()
            if gw.has_registered_tokens:
                if raw_hdr is not None and tok is None:
                    raise GatewayAuthError("Unauthorized: malformed Authorization header.")
                return gw.authenticate_bearer_token(tok)
            if raw_hdr is not None:
                raise GatewayAuthError("Unauthorized: unknown Bearer token (not in token registry).")
            return "default"

        def do_GET(self) -> None:
            try:
                self._authenticate_request()
            except GatewayAuthError as exc:
                self._send_json(401, {"error": str(exc)})
                return
            if self.path == "/health":
                ok, detail = gw.engine.verify_ledger_integrity()
                self._send_json(200, {
                    "status": "healthy" if ok else "degraded",
                    "version": __version__,
                    "concept_doi": __concept_doi__,
                    "doi": __doi__,
                    "vrk_chain_status": detail,
                    "ledger_length": len(gw.engine.ledger),
                    "worker_epoch": gw.engine.epoch_guard.worker_epoch,
                })
            else:
                self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            try:
                authed_tenant = self._authenticate_request()
            except GatewayAuthError as exc:
                self._send_json(401, {"error": str(exc)})
                return

            if self.path == "/v1/execute":
                raw_len = self.headers.get("Content-Length", "0")
                try:
                    length = int(raw_len)
                except ValueError:
                    self._send_json(400, {"error": "Invalid Content-Length header."})
                    return
                if length < 0:
                    self._send_json(400, {"error": "Negative Content-Length header."})
                    return
                if length > max_content_length:
                    self._send_json(413, {
                        "error": f"Payload Too Large: Content-Length {length} exceeds limit ({max_content_length} bytes)."
                    })
                    return

                body_bytes = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    req_data = json.loads(body_bytes.decode("utf-8"))
                    if not isinstance(req_data, dict):
                        raise GatewayConfigError("Request JSON payload must be an object.")
                    prompt = str(req_data.get("prompt", ""))
                    provider = str(req_data.get("provider", "groq"))
                    req_tenant = req_data.get("tenant_id")
                    if req_tenant is not None and str(req_tenant).strip() != authed_tenant:
                        raise GatewayAuthError(
                            f"Unauthorized: token is bound to tenant '{authed_tenant}', cannot impersonate '{req_tenant}'."
                        )
                    tenant_id = authed_tenant or "default"
                    result = gw.process_request(prompt=prompt, provider=provider, tenant_id=tenant_id)
                    self._send_json(200, result)
                except GatewayAuthError as exc:
                    self._send_json(401, {"error": str(exc)})
                except GatewayRateLimitError as exc:
                    self._send_json(429, {"error": str(exc)})
                except GatewayCapacityError as exc:
                    self._send_json(503, {"error": str(exc), "status": "CAPACITY_EXCEEDED"})
                except (GatewayConfigError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                    self._send_json(400, {"error": str(exc)})
                except Exception:
                    self._send_json(500, {
                        "error": "Internal gateway verification error (slot poisoned and zeroed).",
                        "status": "FAIL_CLOSED",
                    })
            else:
                self._send_json(404, {"error": "Not found"})

    server = ThreadingHTTPServer((norm_host, port), GatewayHTTPHandler)
    return server, gw


def run_http_gateway_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    allow_remote: bool = False,
    auth_token: Optional[str] = None,
) -> None:
    server, _ = create_gateway_http_server(
        host=host, port=port, allow_remote=allow_remote, auth_token=auth_token
    )
    print(f"The Reggae Shark Protocol (v{__version__}) HTTP Security Gateway listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
