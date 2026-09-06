import os
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

class VerificationEngine:
    """
    Role 4: File Ops & Verification Engine
    Handles pre/post hashing, file deletion operations, recovery comparison, 
    TrustLayer logging (Role 6 integration), and output schema standardization.
    """

    def __init__(self, trust_layer=None):
        self.tl = trust_layer  # Instance of TrustLayer API (Role 6)

    @staticmethod
    def calculate_sha256(file_path: str, chunk_size: int = 65536) -> Optional[str]:
        """Calculates SHA-256 hash of a file safely without loading full content into RAM."""
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
        """Calculates SHA-256 hash directly from byte sequences."""
        return hashlib.sha256(data).hexdigest()

    def compare_recovered_data(self, original_data: bytes, recovered_data: bytes) -> Dict[str, Any]:
        """Compares raw original bytes against carved/recovered bytes to measure data leakage."""
        if not original_data:
            return {"recovery_percentage": 0.0, "recovery_status": "No original data provided"}

        orig_len = len(original_data)
        rec_len = len(recovered_data)
        min_len = min(orig_len, rec_len)
        
        matching_bytes = sum(1 for i in range(min_len) if original_data[i] == recovered_data[i])
        recovery_percentage = (matching_bytes / orig_len) * 100.0 if orig_len > 0 else 0.0

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
        engine_result: Dict[str, Any],
        pre_hash: Optional[str] = None, 
        recovered_data: Optional[bytes] = None,
        original_data: Optional[bytes] = None,
        user_id: str = "operator_01",
        operation_type: str = "DELETE_FILE"
    ) -> Dict[str, Any]:
        """
        Parses SanitizationEngine output or direct file ops to match required API specs,
        and optionally logs to TrustLayer.
        """
        sha256_before = pre_hash or engine_result.get("original_hash")
        file_exists = os.path.exists(file_path)
        sha256_after = self.calculate_sha256(file_path) if file_exists else None

        # Process recovery metrics if byte buffers are provided
        if recovered_data is not None and original_data:
            recovery_info = self.compare_recovered_data(original_data, recovered_data)
        else:
            recovery_info = {"recovery_percentage": 0.0, "recovery_status": "Not Attempted"}

        engine_passed = engine_result.get("status") == "SUCCESS"
        data_destroyed = (recovery_info["recovery_percentage"] == 0.0)
        
        is_verified = engine_passed and data_destroyed
        verdict = "PASS" if is_verified else "FAIL"

        # Log event directly into Role 6 TrustLayer if connected
        if self.tl and hasattr(self.tl, "log_verification_event"):
            self.tl.log_verification_event({
                "event_type": "VERIFICATION_COMPLETE",
                "target": file_path,
                "target_type": "FILE" if os.path.isfile(file_path) or not file_exists else "DEVICE",
                "pre_operation_hash": sha256_before or "N/A",
                "post_operation_hash": sha256_after or "0000000000000000000000000000000000000000000000000000000000000000",
                "hashes_match": (sha256_before == sha256_after) if (sha256_before and sha256_after) else False,
                "verdict": verdict,
                "verified_by_user_id": user_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "notes": engine_result.get("message", "File sanitization verification complete.")
            })

        return {
            "operation": operation_type,
            "path": file_path,
            "status": "SUCCESS" if is_verified else "FAILED",
            "verified": is_verified,
            "sha256_before": sha256_before,
            "sha256_after": sha256_after,
            "error": engine_result.get("message") if not is_verified else None
        }

    def verify_batch(self, operation_type: str, item_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Formats batch operations into standardized output structure."""
        total = len(item_results)
        successful = sum(1 for item in item_results if item.get("status") == "SUCCESS" and item.get("verified"))
        failed = total - successful

        formatted_results = []
        for item in item_results:
            formatted_item = {
                "path": item.get("path"),
                "status": item.get("status"),
                "verified": item.get("verified")
            }
            if item.get("error"):
                formatted_item["error"] = item.get("error")
            formatted_results.append(formatted_item)

        return {
            "operation": operation_type,
            "total": total,
            "successful": successful,
            "failed": failed,
            "results": formatted_results
        }