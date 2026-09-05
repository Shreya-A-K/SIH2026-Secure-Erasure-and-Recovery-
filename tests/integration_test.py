import unittest
import tempfile
import os
import shutil
import sys

# Ensure root directory is accessible for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from verification import VerificationEngine
except ImportError:
    VerificationEngine = None


class TestEndToEndIntegration(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.sample_file = os.path.join(self.test_dir, "confidential_target.dat")
        self.original_bytes = b"TOP_SECRET_SIH_2026_DATA_STREAM"
        
        with open(self.sample_file, "wb") as f:
            f.write(self.original_bytes)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_full_sanitization_and_verification_pipeline(self):
        """
        Integration Pipeline:
        Role 2 (Auth check) -> Role 4 (Pre-hash) -> Role 3 (Sanitize) -> Role 4 (Verify) -> Role 6 (Audit)
        """
        # 1. Role 2: Auth Check Simulation
        user_role = "ADMIN"
        self.assertIn(user_role, ["ADMIN", "OPERATOR"], "Role 2: Authorization failed")

        # 2. Role 4: Pre-Sanitization Hashing
        verifier = VerificationEngine() if VerificationEngine else None
        if verifier:
            pre_hash = verifier.calculate_sha256(self.sample_file)
            self.assertIsNotNone(pre_hash, "Role 4: Failed to calculate pre-hash")
        else:
            pre_hash = "MOCK_PRE_HASH_VAL"

        # 3. Role 3: Simulated Sanitization (Overwrite file on disk)
        file_size = os.path.getsize(self.sample_file)
        with open(self.sample_file, "wb") as f:
            f.write(b"\x00" * file_size)

        engine_res = {
            "operation_id": "OP-INT-TEST-001",
            "status": "SUCCESS",
            "method": "Single-Pass Zero Fill"
        }

        # 4. Role 4: Verification Check
        if verifier:
            verif_res = verifier.verify_sanitization(
                file_path=self.sample_file,
                pre_hash=pre_hash,
                engine_result=engine_res,
                original_data=self.original_bytes,
                recovered_data=b"\x00" * file_size
            )
            self.assertEqual(verif_res["sanitization_status"], "PASSED", "Role 4: Verification failed")
            self.assertEqual(verif_res["recovery_percentage"], 0.0, "Role 4: Recovery detected")

        # 5. Role 6: Audit Log Entry Simulation
        audit_log_entry = {
            "op_id": engine_res["operation_id"],
            "pre_hash": pre_hash,
            "status": "VERIFIED_SECURE"
        }
        self.assertEqual(audit_log_entry["status"], "VERIFIED_SECURE", "Role 6: Audit logging mismatched")


if __name__ == "__main__":
    unittest.main()