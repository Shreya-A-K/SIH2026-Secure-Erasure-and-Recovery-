import unittest
import hashlib
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestRole6TrustLayer(unittest.TestCase):

    def setUp(self):
        self.genesis_hash = "0" * 64

    def build_hash_block(self, prev_hash, operation_id, status):
        payload = f"{prev_hash}|{operation_id}|{status}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def calculate_assurance_score(self, verif_passed, recovery_perc, audit_chained):
        score = 0
        if verif_passed:
            score += 40
        if recovery_perc == 0.0:
            score += 40
        if audit_chained:
            score += 20
        return score

    def test_audit_hash_chain_creation(self):
        block1 = self.build_hash_block(self.genesis_hash, "OP-101", "SUCCESS")
        block2 = self.build_hash_block(block1, "OP-102", "VERIFIED_SECURE")

        self.assertEqual(len(block1), 64)
        self.assertEqual(len(block2), 64)
        self.assertNotEqual(block1, block2)

    def test_audit_hash_chain_tamper_detection(self):
        block1 = self.build_hash_block(self.genesis_hash, "OP-101", "SUCCESS")
        
        # Tampered payload simulation
        tampered_block1 = self.build_hash_block(self.genesis_hash, "OP-101", "FAILED")
        
        block2_original = self.build_hash_block(block1, "OP-102", "VERIFIED")
        block2_tampered = self.build_hash_block(tampered_block1, "OP-102", "VERIFIED")

        self.assertNotEqual(block2_original, block2_tampered)

    def test_assurance_score_full_points(self):
        score = self.calculate_assurance_score(verif_passed=True, recovery_perc=0.0, audit_chained=True)
        self.assertEqual(score, 100)

    def test_assurance_score_reduced_when_recoverable(self):
        score = self.calculate_assurance_score(verif_passed=True, recovery_perc=15.0, audit_chained=True)
        self.assertEqual(score, 60)


if __name__ == "__main__":
    unittest.main()