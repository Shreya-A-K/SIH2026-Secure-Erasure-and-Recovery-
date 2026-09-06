"""
Role 4 - File / Folder Eraser & Verification
==============================================
NO INTEGRATION SPEC WAS PROVIDED FOR THIS ROLE. Person 1's PROPOSED
interface, shaped to match exactly what Role6_API_Contract.docx says
Role 4 must send to Role 6 (log_file_erase_event / log_verification_event
payloads). Confirm function names/inputs with Person 4.
"""

import hashlib
import os
from datetime import datetime, timezone

from backend import role6_trust
from backend.auth.rbac import has_permission

FILE_ERASE_METHODS = ["OVERWRITE_1_PASS", "OVERWRITE_3_PASS", "OVERWRITE_7_PASS"]


def erase_files(paths: list, method: str, user_id: str) -> dict:
    """STUB: doesn't actually touch the filesystem yet. Person 4:
    replace with real secure-delete logic, keep this return shape.
    Gated on ERASE_FILE per Role2.docx - ADMIN and OPERATOR only."""
    if not has_permission("ERASE_FILE"):
        return {"authorized": False, "reason": "Access denied: ERASE_FILE permission required."}

    operation = "SINGLE_FILE" if len(paths) == 1 and os.path.isfile(paths[0] if paths else "") \
        else ("SINGLE_FOLDER" if len(paths) == 1 else "BATCH")

    event = {
        "event_type": "FILE_ERASE_COMPLETE",
        "operation": operation,
        "target_paths": paths,
        "files_total": len(paths),
        "files_succeeded": len(paths),
        "files_failed": 0,
        "method": method,
        "performed_by_user_id": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "notes": "[STUB] simulated erase",
    }
    role6_trust.log_file_erase_event(event)
    return event


def verify_hash(target: str, target_type: str, pre_hash: str, user_id: str, operation_id: str = None) -> dict:
    """STUB: fakes a post-operation hash. Person 4: replace with a
    real SHA-256 read of the target (device or file). operation_id is
    an extra optional field (not in the original Role6 spec table)
    added so Role 6 can correlate events - confirm with Person 4/6.

    NOTE: Role2.docx has no permission specifically named for
    verification - Person 1's assumption is that it belongs to whoever
    just performed the operation (ERASE_FILE for files, SANITIZE_USB
    for devices). Confirm this with Person 2/4."""
    if not (has_permission("ERASE_FILE") or has_permission("SANITIZE_USB")):
        return {"authorized": False, "reason": "Access denied: ERASE_FILE or SANITIZE_USB permission required."}

    post_hash = hashlib.sha256((target + "_wiped").encode()).hexdigest()
    hashes_match = pre_hash == post_hash
    verdict = "FAIL" if hashes_match else "PASS"  # PASS = hash changed = wipe worked

    event = {
        "event_type": "VERIFICATION_COMPLETE",
        "operation_id": operation_id,
        "target": target,
        "target_type": target_type,
        "pre_operation_hash": pre_hash,
        "post_operation_hash": post_hash,
        "hashes_match": hashes_match,
        "verdict": verdict,
        "verified_by_user_id": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "notes": "Hashes differ - confirms wipe altered data as expected." if verdict == "PASS"
                 else "Hashes identical - wipe had no effect.",
    }
    role6_trust.log_verification_event(event)
    return event
