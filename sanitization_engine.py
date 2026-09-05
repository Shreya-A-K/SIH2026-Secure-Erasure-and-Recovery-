import os
import uuid
import hashlib
import json
from datetime import datetime


class SanitizationEngine:

    def __init__(self):
        self.method = "Single-Pass Overwrite"

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
    # Overwrite File
    # ---------------------------------------------
    def overwrite_file(self, file_path):

        operation_id = self.generate_operation_id()

        start_time = datetime.now().isoformat()

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

            # -----------------------------------------
            # Only TXT files for current prototype
            # -----------------------------------------

            if analysis["extension"] != ".txt":

                result["message"] = (
                    "Prototype currently supports only .txt files"
                )

                return result

            # -----------------------------------------
            # Original SHA-256
            # -----------------------------------------

            original_hash = self.calculate_hash(file_path)

            result["original_hash"] = original_hash
            result["original_size"] = analysis["size_bytes"]

            file_size = analysis["size_bytes"]

            # -----------------------------------------
            # Safety Confirmation
            # -----------------------------------------

            print("\nWARNING: This operation will destroy file contents.")

            confirmation = input(
                "Type ERASE to continue: "
            )

            if confirmation != "ERASE":

                result["message"] = "Operation cancelled by user"

                return result

            # -----------------------------------------
            # Overwrite with zero bytes
            # -----------------------------------------

            chunk_size = 1024 * 1024
            zero_block = b"\x00" * chunk_size

            with open(file_path, "r+b") as file:

                remaining = file_size

                while remaining > 0:

                    write_size = min(
                        remaining,
                        chunk_size
                    )

                    file.write(
                        zero_block[:write_size]
                    )

                    remaining -= write_size

                file.flush()

                os.fsync(file.fileno())

            # -----------------------------------------
            # Verification
            # -----------------------------------------

            sanitized_hash = self.calculate_hash(file_path)

            result["sanitized_hash"] = sanitized_hash

            expected_hash = hashlib.sha256(
                b"\x00" * file_size
            ).hexdigest()

            if sanitized_hash == expected_hash:

                result["status"] = "SUCCESS"
                result["message"] = (
                    "File successfully overwritten and verified"
                )

            else:

                result["status"] = "FAILURE"
                result["message"] = (
                    "Sanitization verification failed"
                )

            result["end_time"] = datetime.now().isoformat()

            return result

        except Exception as e:

            result["status"] = "FAILURE"
            result["message"] = str(e)
            result["end_time"] = datetime.now().isoformat()

            return result


# =================================================
# MAIN
# =================================================

if __name__ == "__main__":

    engine = SanitizationEngine()

    print("===================================")
    print("     SIH SANITIZATION ENGINE")
    print("===================================")

    file_path = input(
        "\nEnter test .txt file path: "
    ).strip()

    result = engine.overwrite_file(file_path)

    print("\n===================================")
    print("          JSON RESULT")
    print("===================================")

    print(
        json.dumps(
            result,
            indent=4
        )
    )