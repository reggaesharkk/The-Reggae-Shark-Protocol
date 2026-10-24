import hashlib
import json
import numpy as np
from scipy.integrate import solve_ivp

class SharkProtocolEngine:
    def __init__(self):
        self.ledger = []
        self.trust_root_hash = None
        self._init_ledger()

    def _init_ledger(self):
        genesis = {
            "protocol": "The Shark Protocol",
            "version": "v1.0.1",
            "axiom": "Build. Attack. Falsify. Preserve.",
            "status": "INITIALIZED"
        }
        gen_str = json.dumps(genesis, sort_keys=True)
        self.trust_root_hash = hashlib.sha256(gen_str.encode('utf-8')).hexdigest()
        self.ledger.append({"index": 0, "payload": genesis, "hash": self.trust_root_hash})

    def verify_and_seal_claim(self, claim_data):
        required_keys = ["claim_id", "proposition", "evidence_class", "dependency_dag", "authority"]
        for key in required_keys:
            if key not in claim_data:
                return False, f"REJECTED: Missing required key '{key}'"

        valid_classes = ["PROVED", "CERTIFIED", "REPRODUCED", "SIMULATED", "DIAGNOSTIC", "FALSIFIED", "OPEN"]
        if claim_data["evidence_class"] not in valid_classes:
            return False, f"REJECTED: Invalid evidence class '{claim_data['evidence_class']}'"

        payload_str = json.dumps(claim_data, sort_keys=True)
        claim_digest = hashlib.sha256(payload_str.encode('utf-8')).hexdigest()
        
        entry = {
            "index": len(self.ledger),
            "prev_hash": self.ledger[-1]["hash"],
            "claim": claim_data,
            "digest": claim_digest
        }
        entry_hash = hashlib.sha256(json.dumps(entry, sort_keys=True).encode('utf-8')).hexdigest()
        entry["hash"] = entry_hash
        self.ledger.append(entry)
        
        return True, f"SEALED [Digest: {claim_digest[:12]}... LedgerIndex: {entry['index']}]"

    def simulate_4d_governor(self, t_span=(0, 50), P0=0.0, Lambda_eff=0.80, lambda_lucid=2.50):
        b, K, gamma_max = 0.1, 0.05, 10.0
        e, eps_I, eps_H = 3.6, 0.05, 0.05
        f, g = 1.0, 1.0
        mu_Psi = 0.60
        sigma0 = 0.05

        def ode_func(t, x):
            gamma, H_obs, I_dot, Psi = x
            gamma = max(0.0, min(gamma_max, gamma))
            H_obs = max(0.0, min(100.0, H_obs))
            Psi = max(0.0, min(1.0, Psi))

            P_eff = P0 + Lambda_eff * gamma + lambda_lucid * Psi
            f_b = e * np.tanh(I_dot / eps_I) * np.tanh(H_obs / eps_H)
            R_self = (f_b ** 2) / (f_b ** 2 + (f * P0) ** 2 + sigma0 ** 2)
            
            d_gamma = -b * gamma + K * (gamma_max - gamma)
            d_Hobs = f_b - H_obs
            d_Idot = f * P_eff - g * I_dot
            d_Psi = mu_Psi * (R_self - Psi)
            
            return [d_gamma, d_Hobs, d_Idot, d_Psi]

        x0 = [2.05, 15.0, 4.0, 0.85]
        sol = solve_ivp(ode_func, t_span, x0, method='RK45', rtol=1e-8, atol=1e-10)
        return sol

    def lrsc_compress(self, vector_data, K_target=11, M=99):
        data_M = np.resize(vector_data, M)
        dft_coeffs = np.fft.fft(data_M)
        magnitudes = np.abs(dft_coeffs)
        top_k_indices = np.argsort(magnitudes)[-K_target:]
        
        reconstructed_dft = np.zeros(M, dtype=complex)
        reconstructed_dft[top_k_indices] = dft_coeffs[top_k_indices]
        reconstructed_signal = np.real(np.fft.ifft(reconstructed_dft))
        
        rel_error = np.linalg.norm(data_M - reconstructed_signal) / np.linalg.norm(data_M)
        
        return {
            "compression_ratio": f"{K_target}/{M} (1/9th)",
            "indices": top_k_indices.tolist(),
            "relative_l2_error": float(rel_error)
        }
