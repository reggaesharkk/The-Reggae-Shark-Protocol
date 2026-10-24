import unittest
from shark_protocol.kernel import SharkProtocolEngine

class TestSharkCore(unittest.TestCase):
    def test_kernel(self):
        eng = SharkProtocolEngine()
        claim = eng.seal_claim("Test proposition")
        self.assertTrue("digest" in claim)

if __name__ == "__main__":
    unittest.main()
