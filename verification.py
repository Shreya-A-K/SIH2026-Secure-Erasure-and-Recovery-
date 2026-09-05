import os
import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

# Setup logger for operational and audit logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

class VerificationEngine:
    """
    Role 4: File Ops & Verification Engine
    Handles pre/post hashing, recovery testing comparison, and verification reporting.
    """

    @staticmethod
    def calculate_sha256(file_path: str, chunk_size: int = 65536) -> Optional[str]:
        """Generates SHA-256 hash of a file."""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return None
        
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, OSError):
            return None

    @staticmethod
    def calculate_bytes_sha256(data: bytes) -> str:
        """Generates SHA-256 hash of raw bytes."""
        return hashlib.sha256(data).hexdigest()

    def compare_recovered_data(self, original_data: bytes, recovered_data: bytes) -> Dict[str, Any]:
        """
        Calculates recovery percentage and determines if data is recoverable.
        """
        if not original_data:
            return {"recovery_percentage": 0.0, "status": "No original data provided"}

        orig_len = len(original_data)
        rec_len = len(recovered_data)
        
        # Calculate matching byte count
        min_len = min(orig_len, rec_len)
        matching_bytes = sum(1 for i in range(min_len) if original_data[i] == recovered_data[i])
        
        recovery_percentage = (matching_bytes / orig_len) * 100.0

        if recovery_percentage == 100.0:
            rec_status = "Completely Recoverable"
        elif recovery_percentage > 0.0:
            rec_status = "Partially Recoverable"
        else:
            rec_status = "Non-recoverable"

        return {
            "recovery_percentage": round(recovery_percentage, 2),
            "matching_bytes": matching_bytes,
            "original_size": orig_len,
            "recovered_size": rec_len,
            "recovery_status": rec_status
        }

    def verify_sanitization(
        self, 
        file_path: str, 
        pre_hash: Optional[str], 
        engine_result: Dict[str, Any],
        recovered_data: Optional[bytes] = None,
        original_data: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Performs full verification pass on a single file operation.
        """
        timestamp = datetime.now().isoformat()
        logs = []

        logs.append(f"Verification started for path: {file_path}")

        # 1. Accessibility Check
        file_exists = os.path.exists(file_path)
        logs.append(f"File exists on disk: {file_exists}")

        # 2. Post-Operation Hash Calculation
        post_hash = self.calculate_sha256(file_path) if file_exists else None
        if post_hash:
            logs.append(f"Post-operation hash calculated: {post_hash}")
        else:
            logs.append("Post-operation hash: File unreadable or deleted.")

        # 3. Hash Comparison Logic
        hash_mismatch = False
        if pre_hash and post_hash:
            hash_mismatch = (pre_hash != post_hash)
            hash_result_str = "HASH_MISMATCH" if hash_mismatch else "HASH_MATCH"
        elif pre_hash and not post_hash:
            hash_result_str = "FILE_REMOVED_OR_ACCESSIBLE_ERROR"
        else:
            hash_result_str = "NO_PRE_HASH"

        logs.append(f"Hash Comparison Status: {hash_result_str}")

        # 4. Recovery Data Analysis
        recovery_attempted = recovered_data is not None
        recovery_info = {}
        if recovery_attempted and original_data:
            recovery_info = self.compare_recovered_data(original_data, recovered_data)
            logs.append(f"Recovery Analysis: {recovery_info['recovery_status']} ({recovery_info['recovery_percentage']}%)")
        else:
            recovery_info = {
                "recovery_percentage": 0.0,
                "recovery_status": "Not Attempted"
            }

        # 5. Define Verification Criteria Rules
        # Sanitization passes if: engine succeeded AND file is non-recoverable AND (file is gone OR hash altered)
        engine_passed = engine_result.get("status") == "SUCCESS"
        data_destroyed = (recovery_info["recovery_percentage"] == 0.0)
        file_altered = (not file_exists) or hash_mismatch

        if engine_passed and data_destroyed and file_altered:
            sanitization_status = "PASSED"
            verification_status = "VERIFIED_SECURE"
        else:
            sanitization_status = "FAILED"
            verification_status = "VERIFICATION_FAILED"

        logs.append(f"Final Sanitization Status: {sanitization_status}")

        result = {
            "operation_id": engine_result.get("operation_id", "UNKNOWN"),
            "file_path": file_path,
            "original_sha256": pre_hash,
            "post_operation_sha256": post_hash,
            "hash_verification_result": hash_result_str,
            "sanitization_status": sanitization_status,
            "verification_status": verification_status,
            "recovery_attempted": recovery_attempted,
            "recovery_percentage": recovery_info.get("recovery_percentage", 0.0),
            "recovery_details": recovery_info.get("recovery_status", "N/A"),
            "file_accessible": file_exists,
            "timestamp": timestamp,
            "error_info": engine_result.get("message") if sanitization_status == "FAILED" else None,
            "audit_logs": logs
        }

        logging.info(f"[{verification_status}] {file_path}")
        return result

    def verify_batch(self, batch_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Processes multi-file or folder batch operations.
        """
        summary = {
            "total_files": len(batch_results),
            "verified_passed": 0,
            "verified_failed": 0,
            "details": batch_results
        }
        for item in batch_results:
            if item.get("verification_status") == "VERIFIED_SECURE":
                summary["verified_passed"] += 1
            else:
                summary["verified_failed"] += 1
        return summary


# =====================================================================
# UNIT TESTS & TESTING SCENARIOS
# =====================================================================

if __name__ == "__main__":
    import unittest
    import tempfile
    import shutil

    class TestVerificationEngine(unittest.TestCase):

        def setUp(self):
            self.verifier = VerificationEngine()
            self.test_dir = tempfile.mkdtemp()
            self.valid_file = os.path.join(self.test_dir, "test.txt")
            self.empty_file = os.path.join(self.test_dir, "empty.txt")
            
            with open(self.valid_file, "wb") as f:
                f.write(b"CONFIDENTIAL_DATA_12345")
                
            with open(self.empty_file, "wb") as f:
                f.write(b"")

        def tearDown(self):
            shutil.rmtree(self.test_dir)

        def test_valid_file_and_hash(self):
            pre_hash = self.verifier.calculate_sha256(self.valid_file)
            self.assertIsNotNone(pre_hash)

        def test_empty_file(self):
            pre_hash = self.verifier.calculate_sha256(self.empty_file)
            # Empty file has a known SHA-256 hash
            self.assertEqual(pre_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        def test_missing_file(self):
            missing = os.path.join(self.test_dir, "non_existent.txt")
            self.assertIsNone(self.verifier.calculate_sha256(missing))

        def test_successful_sanitization_verification(self):
            orig_bytes = b"SECRET"
            pre_hash = self.verifier.calculate_bytes_sha256(orig_bytes)
            
            # Overwrite file on disk
            with open(self.valid_file, "wb") as f:
                f.write(b"\x00\x00\x00\x00\x00\x00")

            engine_res = {"status": "SUCCESS", "operation_id": "OP_123"}
            res = self.verifier.verify_sanitization(
                file_path=self.valid_file,
                pre_hash=pre_hash,
                engine_result=engine_res,
                original_data=orig_bytes,
                recovered_data=b"\x00\x00\x00\x00\x00\x00"
            )

            self.assertEqual(res["sanitization_status"], "PASSED")
            self.assertEqual(res["hash_verification_result"], "HASH_MISMATCH")
            self.assertEqual(res["recovery_percentage"], 0.0)

        def test_data_recovery_scenarios(self):
            orig = b"1234567890"
            
            # 1. Fully Recoverable
            res1 = self.verifier.compare_recovered_data(orig, b"1234567890")
            self.assertEqual(res1["recovery_percentage"], 100.0)
            self.assertEqual(res1["recovery_status"], "Completely Recoverable")

            # 2. Partially Recoverable
            res2 = self.verifier.compare_recovered_data(orig, b"12345XXXXX")
            self.assertEqual(res2["recovery_percentage"], 50.0)
            self.assertEqual(res2["recovery_status"], "Partially Recoverable")

            # 3. Non-Recoverable
            res3 = self.verifier.compare_recovered_data(orig, b"XXXXXXXXXX")
            self.assertEqual(res3["recovery_percentage"], 0.0)
            self.assertEqual(res3["recovery_status"], "Non-recoverable")

    print("\n==========================================")
    print("      RUNNING VERIFICATION UNIT TESTS     ")
    print("==========================================\n")
    unittest.main(verbosity=2)