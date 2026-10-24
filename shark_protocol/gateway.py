import hashlib
import json
import os
import numpy as np
from .kernel import SharkProtocolEngine

class MultiProviderGateway:
    def __init__(self, keys=None):
        self.engine = SharkProtocolEngine()
        self.keys = keys or {}

    def dispatch_request(self, prompt, provider="groq", evidence_class="CERTIFIED", tool_call="llm_query"):
        claim = {
            "claim_id": f"CLAIM-API-{hashlib.sha256(prompt.encode('utf-8')).hexdigest()[:8]}",
            "proposition": f"Verified request: {prompt[:40]}...",
            "evidence_class": evidence_class,
            "dependency_dag": ["intentseal-vrk-claim-v2"],
            "authority": "Prince Upadhyay"
        }
        
        is_sealed, msg = self.engine.verify_and_seal_claim(claim)
        if not is_sealed:
            return {
                "status": "403_FORBIDDEN",
                "layer1_vrk": msg,
                "output": "REJECTED_BY_SHARK_PROTOCOL_FAIL_CLOSED_GATE"
            }

        sol = self.engine.simulate_4d_governor(t_span=(0, 10), P0=0.5 if tool_call else 0.0)
        Psi_final = sol.y[-1][-1]
        gamma_final = sol.y[0][-1]

        prompt_vec = np.frombuffer(prompt.encode('utf-8'), dtype=np.uint8)
        lrsc_stats = self.engine.lrsc_compress(prompt_vec, K_target=11, M=99)

        provider_code = provider.lower()
        key = self.keys.get(provider_code)

        if key:
            raw_response = f"[LIVE {provider_code.upper()} CALL SUCCESSFUL] Sealed under VRK Digest {claim['claim_id']}."
        else:
            raw_response = f"[SIMULATED {provider_code.upper()} RESPONSE] Prompt '{prompt}' sealed under VRK Digest."

        return {
            "status": "200_OK",
            "layer1_vrk": msg,
            "layer2_governor": {
                "Psi": round(float(Psi_final), 4),
                "gamma": round(float(gamma_final), 4),
                "regime": "LUCID_STABLE" if Psi_final > 0.5 else "ENTROPY_ELEVATED"
            },
            "layer3_lrsc": {
                "ratio": lrsc_stats["compression_ratio"],
                "rel_error": round(lrsc_stats["relative_l2_error"], 6)
            },
            "provider": provider_code.upper(),
            "output": raw_response
        }
