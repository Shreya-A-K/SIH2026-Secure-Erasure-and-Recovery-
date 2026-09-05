import unittest
import tempfile
import os
import shutil
import sys
from unittest.mock import patch

# Ensure root directory is in the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from verification import VerificationEngine


class TestRole4Verification(unittest.TestCase):

    def setUp(self):
        self.verifier = VerificationEngine()
        self.test_dir = tempfile.mkdtemp()
        self.sample_file = os.path.join(self.test_dir, "sample.txt")
        self.empty_file = os.path.join(self.test_dir, "empty.txt")
        
        with open(self.sample_file, "wb") as f:
            f.write(b"CONFIDENTIAL_ORIGINAL_DATA")
            
        with open(self.empty_file, "wb") as f:
            f.write(b"")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    # -------------------------------------------------------------------------
    # Hashing Tests
    # -------------------------------------------------------------------------

    def test_sha256_generation_valid_file(self):
        pre_hash = self.verifier.calculate_sha256(self.sample_file)
        self.assertIsNotNone(pre_hash)
        self.assertEqual(len(pre_hash), 64)

    def test_sha256_empty_file(self):
        empty_hash = self.verifier.calculate_sha256(self.empty_file)
        self.assertEqual(
            empty_hash, 
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_sha256_missing_file(self):
        missing_path = os.path.join(self.test_dir, "non_existent.txt")
        self.assertIsNone(self.verifier.calculate_sha256(missing_path))

    def test_sha256_permission_failure(self):
        with patch("builtins.open", side_effect=PermissionError):
            result = self.verifier.calculate_sha256(self.sample_file)
            self.assertIsNone(result)

    def test_hash_mismatch_after_overwrite(self):
        pre_hash = self.verifier.calculate_sha256(self.sample_file)
        
        with open(self.sample_file, "wb") as f:
            f.write(b"\x00" * 26)

        post_hash = self.verifier.calculate_sha256(self.sample_file)
        self.assertNotEqual(pre_hash, post_hash)

    # -------------------------------------------------------------------------
    # Data Recovery Comparison Scenarios
    # -------------------------------------------------------------------------

    def test_recovery_completely_recoverable(self):
        original = b"SECRET_KEY_123"
        recovered = b"SECRET_KEY_123"
        res = self.verifier.compare_recovered_data(original, recovered)
        self.assertEqual(res["recovery_percentage"], 100.0)
        self.assertEqual(res["recovery_status"], "Completely Recoverable")

    def test_recovery_partially_recoverable(self):
        original = b"SECRET_KEY_123"
        recovered = b"SECRET_KEY_000"
        res = self.verifier.compare_recovered_data(original, recovered)
        self.assertGreater(res["recovery_percentage"], 0.0)
        self.assertLess(res["recovery_percentage"], 100.0)
        self.assertEqual(res["recovery_status"], "Partially Recoverable")

    def test_recovery_non_recoverable(self):
        original = b"SECRET_KEY_123"
        recovered = b"\x00" * 14
        res = self.verifier.compare_recovered_data(original, recovered)
        self.assertEqual(res["recovery_percentage"], 0.0)
        self.assertEqual(res["recovery_status"], "Non-recoverable")

    # -------------------------------------------------------------------------
    # Sanitization Verification & Edge Cases
    # -------------------------------------------------------------------------

    def test_sanitization_verification_pass(self):
        pre_hash = self.verifier.calculate_sha256(self.sample_file)
        engine_result = {"status": "SUCCESS", "operation_id": "OP-1001"}

        # Simulate wiped file
        with open(self.sample_file, "wb") as f:
            f.write(b"\x00" * 26)

        res = self.verifier.verify_sanitization(
            file_path=self.sample_file,
            pre_hash=pre_hash,
            engine_result=engine_result,
            original_data=b"CONFIDENTIAL_ORIGINAL_DATA",
            recovered_data=b"\x00" * 26
        )

        self.assertEqual(res["sanitization_status"], "PASSED")
        self.assertEqual(res["verification_status"], "VERIFIED_SECURE")
        self.assertIn("audit_logs", res)

    def test_sanitization_verification_failed_engine(self):
        pre_hash = self.verifier.calculate_sha256(self.sample_file)
        engine_result = {"status": "FAILED", "operation_id": "OP-1002", "message": "Write permission denied"}

        res = self.verifier.verify_sanitization(
            file_path=self.sample_file,
            pre_hash=pre_hash,
            engine_result=engine_result
        )

        self.assertEqual(res["sanitization_status"], "FAILED")
        self.assertEqual(res["verification_status"], "VERIFICATION_FAILED")

    def test_sanitization_already_deleted_file(self):
        pre_hash = self.verifier.calculate_sha256(self.sample_file)
        os.remove(self.sample_file)  # Delete file before verification check

        engine_result = {"status": "SUCCESS", "operation_id": "OP-1003"}
        res = self.verifier.verify_sanitization(
            file_path=self.sample_file,
            pre_hash=pre_hash,
            engine_result=engine_result
        )

        self.assertFalse(res["file_accessible"])
        self.assertEqual(res["sanitization_status"], "PASSED")

    def test_verify_batch_operation(self):
        batch_items = [
            {"verification_status": "VERIFIED_SECURE"},
            {"verification_status": "VERIFIED_SECURE"},
            {"verification_status": "VERIFICATION_FAILED"}
        ]
        summary = self.verifier.verify_batch(batch_items)
        self.assertEqual(summary["total_files"], 3)
        self.assertEqual(summary["verified_passed"], 2)
        self.assertEqual(summary["verified_failed"], 1)


if __name__ == "__main__":
    unittest.main()