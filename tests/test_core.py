import unittest
import numpy as np
from shark_protocol.kernel import SharkProtocolEngine
from shark_protocol.gateway import MultiProviderGateway

class TestSharkProtocolCore(unittest.TestCase):
    def setUp(self):
        self.engine = SharkProtocolEngine()
        self.gateway = MultiProviderGateway()

    def test_ledger_initialization(self):
        self.assertEqual(len(self.engine.ledger), 1)
        self.assertIsNotNone(self.engine.trust_root_hash)

    def test_vrk_claim_sealing(self):
        claim = {
            "claim_id": "TEST-001",
            "proposition": "Unit test proposition",
            "evidence_class": "CERTIFIED",
            "dependency_dag": ["root"],
            "authority": "Prince Upadhyay"
        }
        is_sealed, msg = self.engine.verify_and_seal_claim(claim)
        self.assertTrue(is_sealed)
        self.assertIn("SEALED", msg)

    def test_governor_simulation(self):
        sol = self.engine.simulate_4d_governor(t_span=(0, 10))
        self.assertEqual(len(sol.y), 4)

    def test_lrsc_compression(self):
        vec = np.ones(99)
        stats = self.engine.lrsc_compress(vec, K_target=11, M=99)
        self.assertEqual(stats["compression_ratio"], "11/99 (1/9th)")

if __name__ == "__main__":
    unittest.main()
