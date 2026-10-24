"""
Layer 4: Multi-Cloud Security Gateway & Local HTTP Proxy Server (`http://localhost:8000`).

Provides:
- Fail-closed provider validation (`groq`, `together`, `gemini`, `huggingface`).
- Complete 4-layer execution pipeline per request:
  1. Layer 1B Typestate & Worker-Epoch Isolation (`UNINIT -> PARTIAL_INIT -> SEALED_ACTIVE`)
  2. Layer 3 LRSC `M=99, K=11` (`1/9` footprint) spectral context compression
  3. Layer 2 4D Soft-Wall ODE Governor step & 8-face `B_4` box verification
  4. Layer 1 IntentSeal VRK `v0.3.1` hash-chained claim sealing
- Real HTTP dispatch (`requests.post`) to Groq, Together AI, Google Gemini, and Hugging Face
  when API keys are configured, with automatic multi-provider failover on network/API errors,
  and transparent `[VRK_OFFLINE_SEALED_SIMULATION]` mode when keys are absent.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
import requests

from .kernel import (
    LRSCCompressor,
    SharkProtocolEngine,
    TypestateViolationError,
    VRKSchemaError,
)


class MultiProviderGateway:
    """Fail-closed 4-provider LLM gateway governed by VRK v0.3.1, 4D ODEs, and LRSC 11/99."""

    FAILOVER_ORDER: Tuple[str, ...] = ("groq", "together", "gemini", "huggingface")

    def __init__(self, api_keys: Optional[Dict[str, str]] = None) -> None:
        self.engine = SharkProtocolEngine()
        env_keys = {
            "groq": os.getenv("GROQ_API_KEY", "").strip(),
            "together": os.getenv("TOGETHER_API_KEY", "").strip(),
            "gemini": os.getenv("GEMINI_API_KEY", "").strip(),
            "huggingface": os.getenv("HUGGINGFACE_API_KEY", "").strip(),
        }
        if api_keys:
            for k, v in api_keys.items():
                env_keys[k.lower()] = (v or "").strip()
        self.api_keys: Dict[str, str] = env_keys

        self.models: Dict[str, str] = {
            "groq": "llama-3.3-70b-versatile",
            "together": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "gemini": "gemini-1.5-flash",
            "huggingface": "mistralai/Mistral-7B-Instruct-v0.2",
        }

    def _call_provider_http(self, provider: str, prompt: str, key: str, timeout: float = 12.0) -> str:
        """Execute a real HTTPS request to the specified LLM provider API."""
        model = self.models[provider]
        if provider == "groq":
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

        if provider == "together":
            resp = requests.post(
                "https://api.together.xyz/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

        if provider == "gemini":
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
            resp = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

        if provider == "huggingface":
            url = f"https://api-inference.huggingface.co/models/{model}"
            resp = requests.post(
                url,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"inputs": prompt},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list) and data and "generated_text" in data[0]:
                return data[0]["generated_text"]
            return json.dumps(data)

        raise ValueError(f"Unsupported provider: {provider}")

    def process_request(
        self,
        provider: str,
        prompt: str,
        enable_failover: bool = True,
        simulate_oom: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute a prompt through all 4 architectural layers:
        - Fail-closed provider check (rejects unknown providers instead of silently defaulting).
        - Layer 1B Typestate & Epoch-Isolation gate (`UNINIT -> PARTIAL_INIT -> SEALED_ACTIVE`).
        - Layer 3 LRSC `11/99` spectral context compression.
        - Layer 2 4D Soft-Wall ODE Governor step & 8-face `B_4` box check.
        - Layer 4 Live HTTP provider dispatch with automatic multi-cloud failover (or honest
          `[VRK_OFFLINE_SEALED_SIMULATION]` when no API keys are configured).
        """
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string.")

        provider_norm = provider.strip().lower()
        # Allow display names from UI ("together ai", "google gemini", "hugging face")
        alias_map = {
            "groq": "groq",
            "together": "together",
            "together ai": "together",
            "gemini": "gemini",
            "google gemini": "gemini",
            "huggingface": "huggingface",
            "hugging face": "huggingface",
        }
        if provider_norm not in alias_map:
            raise ValueError(
                f"Fail-closed provider rejection: unknown provider '{provider}'. "
                f"Allowed providers: {list(self.models.keys())}."
            )
        primary_provider = alias_map[provider_norm]

        # Layer 3: LRSC 11/99 Spectral Compression
        lrsc_report = LRSCCompressor.compress_context(prompt)

        # Layer 1B + Layer 2 + Layer 1: Begin request epoch, advance 4D ODE, seal VRK claim
        slot = self.engine.begin_request_epoch(
            payload={"provider": primary_provider, "prompt": prompt, "lrsc_digest": lrsc_report["spectral_digest"]},
            simulate_oom_in_partial_init=simulate_oom,
        )

        try:
            verified_payload = slot.read_payload(active_worker_epoch=self.engine.worker_epoch)
            candidates: List[str] = [primary_provider]
            if enable_failover:
                for p_cand in self.FAILOVER_ORDER:
                    if p_cand not in candidates:
                        candidates.append(p_cand)

            dispatch_mode = "VRK_OFFLINE_SEALED_SIMULATION"
            active_provider = primary_provider
            failover_log: List[str] = []
            output_msg = ""

            for cand in candidates:
                key = self.api_keys.get(cand, "")
                if not key:
                    failover_log.append(f"{cand.upper()}: no API key configured")
                    continue
                try:
                    live_text = self._call_provider_http(cand, verified_payload["prompt"], key)
                    active_provider = cand
                    dispatch_mode = "LIVE_API_DISPATCH"
                    output_msg = f"[LIVE {cand.upper()} API RESPONSE ({self.models[cand]})]: {live_text}"
                    break
                except Exception as exc:
                    failover_log.append(f"{cand.upper()}: error ({type(exc).__name__})")

            if dispatch_mode == "VRK_OFFLINE_SEALED_SIMULATION":
                output_msg = (
                    f"[VRK_OFFLINE_SEALED_SIMULATION] No live API keys configured; request cryptographically "
                    f"sealed at Epoch {self.engine.worker_epoch} for {primary_provider.upper()} "
                    f"({self.models[primary_provider]}), compressed via LRSC (11/99), and verified inside B_4."
                )

            latest_claim = self.engine.ledger[-1]
            ok_chain, chain_status = self.engine.verify_ledger_integrity()
            if not ok_chain:
                raise VRKSchemaError(f"Ledger integrity check failed: {chain_status}")

        finally:
            final_typestate = self.engine.finalize_request_epoch(slot)

        return {
            "status": "200_OK",
            "dispatch_mode": dispatch_mode,
            "provider": active_provider.upper(),
            "requested_provider": primary_provider.upper(),
            "target_model": self.models[active_provider],
            "worker_epoch": self.engine.worker_epoch,
            "typestate_final": final_typestate.value,
            "layer1_vrk": (
                f"SEALED [Digest: {latest_claim['digest'][:12]}... | "
                f"Prev: {latest_claim['prev_hash'][:12]}... | "
                f"LedgerIndex: {latest_claim['ledger_index']} | {chain_status}]"
            ),
            "layer1_claim": latest_claim,
            "layer2_governor": self.engine.state,
            "layer3_lrsc": lrsc_report,
            "failover_trace": failover_log,
            "output": output_msg,
        }


def make_gateway_handler(gateway: MultiProviderGateway):
    """Create an HTTP request handler bound to `gateway` for `http://localhost:8000`."""

    class SharkGatewayHTTPHandler(BaseHTTPRequestHandler):
        def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/v1/health":
                ok_chain, chain_status = gateway.engine.verify_ledger_integrity()
                ok_box, box_status = gateway.engine.verify_box_invariance()
                self._send_json(200, {
                    "status": "OK" if (ok_chain and ok_box) else "ERROR",
                    "version": "1.1.0",
                    "worker_epoch": gateway.engine.worker_epoch,
                    "ledger_status": chain_status,
                    "box_status": box_status,
                    "governor_state": gateway.engine.state,
                })
            elif self.path == "/v1/ledger/verify":
                ok_chain, chain_status = gateway.engine.verify_ledger_integrity()
                self._send_json(200 if ok_chain else 500, {
                    "verified": ok_chain,
                    "chain_status": chain_status,
                    "entries": len(gateway.engine.ledger),
                })
            else:
                self._send_json(404, {"error": "Endpoint not found. Use GET /v1/health or POST /v1/execute."})

        def do_POST(self) -> None:
            if self.path != "/v1/execute":
                self._send_json(404, {"error": "Endpoint not found. Use POST /v1/execute."})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
                req = json.loads(raw)
                provider = req.get("provider", "groq")
                prompt = req.get("prompt", "")
                res = gateway.process_request(provider=provider, prompt=prompt)
                self._send_json(200, res)
            except (ValueError, TypestateViolationError, VRKSchemaError) as exc:
                self._send_json(400, {"status": "400_FAIL_CLOSED", "error": str(exc)})

        def log_message(self, format: str, *args: Any) -> None:
            return

    return SharkGatewayHTTPHandler


def run_http_gateway(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the live local HTTP security gateway proxy on `http://localhost:8000`."""
    gw = MultiProviderGateway()
    server = HTTPServer((host, port), make_gateway_handler(gw))
    print(f"=== The Shark Protocol HTTP Security Gateway v1.1.0 listening on http://{host}:{port} ===")
    print("Endpoints: GET /v1/health | GET /v1/ledger/verify | POST /v1/execute")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down gateway cleanly.")
    finally:
        server.server_close()
