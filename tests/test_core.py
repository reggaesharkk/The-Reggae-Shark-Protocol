import unittest
import numpy as np
from shark_protocol.kernel import SharkProtocolEngine
from shark_protocol.gateway import MultiProviderGateway

class TestSharkProtocol(unittest.TestCase):
    def setUp(self):
        self.engine = SharkProtocolEngine()
        self.gateway = MultiProviderGateway()

    def test_layer1_vrk_seal_and_reject(self):
        valid_claim = {
            "claim_id": "TEST-001",
            "proposition": "Psi-memory zero-drive limit cycle stays bounded in B4",
            "evidence_class": "PROVED",
            "dependency_dag": ["ExistenceVerification.lean"],
            "authority": "Prince Upadhyay"
        }
        status, msg = self.engine.verify_and_seal_claim(valid_claim)
        self.assertTrue(status)
        self.assertIn("SEALED", msg)

        invalid_claim = {"claim_id": "TEST-002", "proposition": "Missing keys"}
        status, msg = self.engine.verify_and_seal_claim(invalid_claim)
        self.assertFalse(status)
        self.assertIn("REJECTED", msg)

    def test_layer2_4d_ode_governor(self):
        sol = self.engine.simulate_4d_governor(t_span=(0, 10), P0=0.0)
        self.assertEqual(len(sol.y), 4)
        Psi_final = sol.y[3][-1]
        self.assertGreater(Psi_final, 0.0)
        self.assertLessEqual(Psi_final, 1.0)

    def test_layer3_lrsc_compression(self):
        mock_data = np.random.randn(99)
        res = self.engine.lrsc_compress(mock_data, K_target=11, M=99)
        self.assertEqual(res["compression_ratio"], "11/99 (1/9th)")
        self.assertEqual(len(res["indices"]), 11)

    def test_gateway_dispatch(self):
        res = self.gateway.dispatch_request("Test prompt", provider="groq")
        self.assertEqual(res["status"], "200_OK")
        self.assertIn("SEALED", res["layer1_vrk"])

if __name__ == "__main__":
    unittest.main()
