"""
Layer 4: Fail-Closed Multi-Cloud Execution Gateway & Hardened Loopback HTTP Proxy (`shark_protocol/gateway.py`)
Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Version: 1.3.1 (Reviewer-Audited Edition | Concept DOI: 10.5281/zenodo.23618032 | Prior v4 DOI: 10.5281/zenodo.23635351)

Hardening Summary (v1.3.1):
1. Strict Fail-Closed Provider Dispatch:
   - Silent cross-provider fallback is disabled by default (`allow_failover=False`).
   - If a live API key is configured for the target provider (or `require_live_dispatch=True`) and
     the external HTTP call fails, `process_request` aborts the request slot (`ABORTED_POISONED` ->
     `ZEROED_FREED`) and raises `GatewayDispatchError` fail-closed.
   - Offline simulation (`VRK_OFFLINE_SEALED_SIMULATION`) runs only when no live API key is configured
     and `require_live_dispatch=False`, cross-checking both `step_ode` (RK4) and
     `step_ode_patankar_interval` (Patankar-Euler) before sealing.
2. Token-Bound Tenant Derivation, Bounded-LRU Isolation & Per-Tenant Rate Limiting:
   - Validates `tenant_id` against `^[A-Za-z0-9_.-]{1,64}$`, binds HTTP tenant identity to the
     authenticated Bearer token (`derive_tenant_from_token`), bounds `_tenant_engines` using an
     `OrderedDict` LRU cache (`max_tenants=128`), and enforces a sliding-window rate limit
     (`rate_limit_per_window=120` per `rate_limit_window_sec=60.0`, returning HTTP 429 when exceeded).
3. Header-Only API Key Transmission:
   - Sends the Google Gemini API key via the `x-goog-api-key` HTTP header, never in the URL query string.
4. Hardened `ThreadingHTTPServer`:
   - Enforces `MAX_HTTP_CONTENT_LENGTH = 65536` (returning HTTP `413 Payload Too Large`).
   - Refuses non-loopback bind hosts unless `allow_remote=True` AND a non-empty Bearer token
     (`auth_token` or `SHARK_GATEWAY_BEARER_TOKEN`) is configured, verified via `hmac.compare_digest`.
   - Returns sanitized JSON on HTTP `500` without leaking internal exception tracebacks (`str(exc)`).
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Deque, Dict, List, Optional, Tuple

import requests
try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    def load_dotenv(*_args, **_kwargs):
        return False

from .kernel import (
    LifecycleEvent,
    SharkProtocolEngine,
    TypestateViolationError,
)

load_dotenv()

TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
MAX_HTTP_CONTENT_LENGTH = 65536


class GatewayConfigError(ValueError):
    """Raised when an invalid provider, tenant_id, or unsafe HTTP bind configuration is requested."""


class GatewayRateLimitError(GatewayConfigError):
    """Raised when a tenant exceeds its configured sliding-window request rate limit."""


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
      2. Layer 2 : Bounded-LRU per-tenant isolated 4D Soft-Wall ODE dual-solver step with waking
                   basal drive floor (`min_waking_p0 >= 1.0 >> P_crit = 10/99`)
      3. Layer 3 : Bandlimited LRSC 11/99 spectral compression (`LRSCCompressor` with prompt commitment)
      4. Layer 1 : Append-only Ed25519-signed `intentseal-vrk-claim-v2` SHA-256 ledger seal
    """

    def __init__(
        self,
        engine: Optional[SharkProtocolEngine] = None,
        min_waking_p0: float = 1.0,
        max_tenants: int = 128,
        signing_seed: Optional[bytes] = None,
        rate_limit_per_window: int = 120,
        rate_limit_window_sec: float = 60.0,
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
        self.engine = engine if engine is not None else SharkProtocolEngine(signing_seed=signing_seed)
        self._gateway_lock = threading.RLock()
        self._tenant_engines: "collections.OrderedDict[str, SharkProtocolEngine]" = collections.OrderedDict()
        self._tenant_engines["default"] = self.engine
        self._tenant_windows: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)

    @staticmethod
    def derive_tenant_from_token(bearer_token: str) -> str:
        """Bind tenant identity deterministically to an authenticated Bearer token."""
        digest = hashlib.sha256(b"shark_tenant_token_binding_v1:" + bearer_token.encode("utf-8")).hexdigest()
        return f"t_{digest[:16]}"

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
        """Return a bounded-LRU isolated `SharkProtocolEngine` for `tenant_id`."""
        norm_id = (tenant_id or "default").strip() or "default"
        if not TENANT_ID_PATTERN.match(norm_id):
            raise GatewayConfigError(
                f"Invalid tenant_id '{tenant_id}': must match ^[A-Za-z0-9_.-]{{1,64}}$."
            )
        with self._gateway_lock:
            if norm_id in self._tenant_engines:
                self._tenant_engines.move_to_end(norm_id)
                return self._tenant_engines[norm_id]

            while len(self._tenant_engines) >= self.max_tenants:
                oldest_key = next(iter(self._tenant_engines))
                if oldest_key == "default" and len(self._tenant_engines) > 1:
                    second_key = list(self._tenant_engines.keys())[1]
                    del self._tenant_engines[second_key]
                    self._tenant_windows.pop(second_key, None)
                else:
                    evicted_key, _ = self._tenant_engines.popitem(last=False)
                    self._tenant_windows.pop(evicted_key, None)

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
                signing_seed=self.engine.signer._seed,
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
            ode_snapshot["patankar_certified"] = patankar_snapshot["inside_B4_certified"]
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
    max_content_length: int = MAX_HTTP_CONTENT_LENGTH,
    bind_tenant_to_token: bool = True,
) -> Tuple[ThreadingHTTPServer, MultiProviderGateway]:
    norm_host = host.strip()
    effective_token = (auth_token if auth_token is not None else os.environ.get("SHARK_GATEWAY_BEARER_TOKEN", "")).strip()

    if norm_host not in LOOPBACK_HOSTS:
        if not allow_remote or not effective_token:
            raise GatewayConfigError(
                f"Refusing to bind HTTP gateway to non-loopback host '{norm_host}' without both "
                f"allow_remote=True and a non-empty SHARK_GATEWAY_BEARER_TOKEN."
            )

    gw = gateway if gateway is not None else MultiProviderGateway()

    class GatewayHTTPHandler(BaseHTTPRequestHandler):
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

        def _check_auth(self) -> bool:
            if not effective_token:
                return True
            hdr = self.headers.get("Authorization", "")
            expected = f"Bearer {effective_token}"
            return hmac.compare_digest(hdr.encode("utf-8"), expected.encode("utf-8"))

        def do_GET(self) -> None:
            if not self._check_auth():
                self._send_json(401, {"error": "Unauthorized: missing or invalid Bearer token."})
                return
            if self.path == "/health":
                ok, detail = gw.engine.verify_ledger_integrity()
                self._send_json(200, {
                    "status": "healthy" if ok else "degraded",
                    "version": "1.3.1",
                    "concept_doi": "10.5281/zenodo.23618032",
                    "doi": "10.5281/zenodo.23618032",
                    "vrk_chain_status": detail,
                    "ledger_length": len(gw.engine.ledger),
                    "worker_epoch": gw.engine.epoch_guard.worker_epoch,
                })
            else:
                self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            if not self._check_auth():
                self._send_json(401, {"error": "Unauthorized: missing or invalid Bearer token."})
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
                    tok = self._extract_bearer_token()
                    if bind_tenant_to_token and tok:
                        tenant_id = gw.derive_tenant_from_token(tok)
                    else:
                        tenant_id = str(req_data.get("tenant_id", "default"))
                    result = gw.process_request(prompt=prompt, provider=provider, tenant_id=tenant_id)
                    self._send_json(200, result)
                except GatewayRateLimitError as exc:
                    self._send_json(429, {"error": str(exc)})
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
    print(f"The Shark Protocol (v1.3.1) HTTP Security Gateway listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
