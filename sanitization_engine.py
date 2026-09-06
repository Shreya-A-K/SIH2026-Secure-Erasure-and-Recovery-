import os
import uuid
import hashlib
import json
from datetime import datetime, timezone


class SanitizationEngine:

    def __init__(self, trust_layer=None):
        self.method = "Single-Pass Overwrite"
        self.tl = trust_layer  # Role 6 Trust Layer instance (optional)

    # ---------------------------------------------
    # Generate Operation ID
    # ---------------------------------------------
    def generate_operation_id(self):
        return "OP-" + uuid.uuid4().hex[:12].upper()

    # ---------------------------------------------
    # Analyze File
    # ---------------------------------------------
    def analyze_device(self, file_path):
        if not os.path.exists(file_path):
            return {
                "success": False,
                "message": "File does not exist"
            }

        if not os.path.isfile(file_path):
            return {
                "success": False,
                "message": "Path is not a file"
            }

        file_size = os.path.getsize(file_path)
        extension = os.path.splitext(file_path)[1].lower()

        return {
            "success": True,
            "path": file_path,
            "name": os.path.basename(file_path),
            "extension": extension,
            "size_bytes": file_size,
            "size_kb": round(file_size / 1024, 2),
            "type": "TEXT FILE" if extension == ".txt" else "UNKNOWN"
        }

    # ---------------------------------------------
    # Calculate SHA-256
    # ---------------------------------------------
    def calculate_hash(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as file:
            while True:
                data = file.read(1024 * 1024)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()

    # ---------------------------------------------
    # Helper: Calculate Expected Hash for Zeros
    # ---------------------------------------------
    def _calculate_zero_hash(self, total_bytes):
        """Calculates expected SHA-256 hash for a zeroed file in chunks without RAM spikes."""
        sha256 = hashlib.sha256()
        chunk_size = 1024 * 1024
        zero_block = b"\x00" * chunk_size
        
        remaining = total_bytes
        while remaining > 0:
            write_size = min(remaining, chunk_size)
            sha256.update(zero_block[:write_size])
            remaining -= write_size
            
        return sha256.hexdigest()

    # ---------------------------------------------
    # Overwrite File
    # ---------------------------------------------
    def overwrite_file(self, file_path, user_id="operator_01", skip_prompt=False):
        operation_id = self.generate_operation_id()
        start_time = datetime.now(timezone.utc).isoformat()

        result = {
            "operation_id": operation_id,
            "method": self.method,
            "path": file_path,
            "start_time": start_time,
            "status": "FAILURE"
        }

        try:
            # -----------------------------------------
            # Analyze
            # -----------------------------------------
            analysis = self.analyze_device(file_path)
            if not analysis["success"]:
                result["message"] = analysis["message"]
                return result

            # Prototype file type check
            if analysis["extension"] != ".txt":
                result["message"] = "Prototype currently supports only .txt files"
                return result

            # -----------------------------------------
            # Original Hash & Metadata
            # -----------------------------------------
            original_hash = self.calculate_hash(file_path)
            result["original_hash"] = original_hash
            result["original_size"] = analysis["size_bytes"]
            file_size = analysis["size_bytes"]

            # -----------------------------------------
            # Safety Confirmation
            # -----------------------------------------
            if not skip_prompt:
                print("\nWARNING: This operation will destroy file contents.")
                confirmation = input("Type ERASE to continue: ").strip()
                if confirmation != "ERASE":
                    result["message"] = "Operation cancelled by user"
                    return result

            # -----------------------------------------
            # Overwrite with Zero Bytes
            # -----------------------------------------
            chunk_size = 1024 * 1024
            zero_block = b"\x00" * chunk_size

            with open(file_path, "r+b") as file:
                remaining = file_size
                while remaining > 0:
                    write_size = min(remaining, chunk_size)
                    file.write(zero_block[:write_size])
                    remaining -= write_size

                file.flush()
                os.fsync(file.fileno())

            # -----------------------------------------
            # Verification
            # -----------------------------------------
            sanitized_hash = self.calculate_hash(file_path)
            result["sanitized_hash"] = sanitized_hash

            # Memory-safe zero-hash calculation
            expected_hash = self._calculate_zero_hash(file_size)

            if sanitized_hash == expected_hash:
                result["status"] = "SUCCESS"
                result["message"] = "File successfully overwritten and verified"
            else:
                result["status"] = "FAILURE"
                result["message"] = "Sanitization verification failed"

            result["end_time"] = datetime.now(timezone.utc).isoformat()

            # Optional hook for logging into TrustLayer
            if self.tl and hasattr(self.tl, "log_sanitization_event"):
                self.tl.log_sanitization_event({
                    "event_type": "SANITIZATION_COMPLETE",
                    "device_path": file_path,
                    "serial": "FILE-MODE",
                    "method": self.method,
                    "passes_completed": 1,
                    "sectors_wiped": 0,
                    "capacity_gb": round(file_size / (1024**3), 6),
                    "status": result["status"],
                    "start_time": result["start_time"],
                    "end_time": result["end_time"],
                    "duration_seconds": 1,
                    "performed_by_user_id": user_id,
                    "notes": result["message"]
                })

            return result

        except Exception as e:
            result["status"] = "FAILURE"
            result["message"] = str(e)
            result["end_time"] = datetime.now(timezone.utc).isoformat()
            return result


# =================================================
# MAIN
# =================================================
if __name__ == "__main__":
    engine = SanitizationEngine()

    print("===================================")
    print("     SIH SANITIZATION ENGINE")
    print("===================================")

    file_path = input("\nEnter test .txt file path: ").strip()
    result = engine.overwrite_file(file_path, skip_prompt=False)

    print("\n===================================")
    print("            JSON RESULT")
    print("===================================")
    print(json.dumps(result, indent=4))