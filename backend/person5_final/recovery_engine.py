"""
Person 5 - Forensics / Recovery
Main recovery / file-carving engine. STUB matching
Person_5_Forensics_Integration_Spec.docx section 1-2 exactly.
"""

import hashlib
from datetime import datetime, timezone

from .confidence_score import score_batch

_SAMPLE_FILES = [
    {"name": "pikachu.png", "method": "pytsk3", "size": 343769},
    {"name": "notes.pdf", "method": "scalpel", "size": 88210},
]


def run_full_recovery(request: dict) -> dict:
    """
    INPUT - Recovery Request:
        {
          "operation_id": "OP-001", "device_path": "./test.img", "scan_type": "FULL",
          "file_types": ["jpg", "png", "pdf"], "output_dir": "./recovered"
        }

    OUTPUT - Recovery Result (matches spec section 2 exactly):
        {
          "operation_id": ..., "status": "COMPLETED", "files_found": int,
          "files": [ {name, method, path, size, confidence_score, confidence_label, sha256} ]
        }
    """
    output_dir = request.get("output_dir", "./recovered")
    raw_files = []
    for f in _SAMPLE_FILES:
        path = f"{output_dir}/{f['method']}/{f['method']}_{f['name']}"
        fake_hash = hashlib.sha256((f["name"] + str(f["size"])).encode()).hexdigest()
        raw_files.append({**f, "path": path, "sha256": fake_hash})

    scored_files = score_batch(raw_files)

    return {
        "operation_id": request.get("operation_id"),
        "status": "COMPLETED",
        "files_found": len(scored_files),
        "files": scored_files,
        "_generated_at": datetime.now(timezone.utc).isoformat(),  # debug only, not in real spec
    }
