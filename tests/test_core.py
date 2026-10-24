import unittest
from shark_protocol.kernel import SharkProtocolEngine
from shark_protocol.gateway import MultiProviderGateway

class TestSharkCore(unittest.TestCase):
    def test_kernel_seal(self):
        eng = SharkProtocolEngine()
        claim = eng.seal_claim("Test proposition")
        self.assertTrue("digest" in claim)
        self.assertEqual(claim["ledger_index"], 1)

    def test_gateway_providers(self):
        gw = MultiProviderGateway()
        for prov in ["groq", "together", "gemini", "huggingface"]:
            res = gw.process_request(prov, "Test prompt")
            self.assertEqual(res["status"], "200_OK")
            self.assertTrue("SEALED" in res["layer1_vrk"])

if __name__ == "__main__":
    unittest.main()
