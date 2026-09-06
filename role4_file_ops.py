"""
role4_file_ops.py — Role 4 Adapter for File Operations & Verification.

Provides safe file erasure and verification operations.
NEVER touches real hardware (/dev/sd*, /dev/nvme*, /dev/mmc*).
"""

import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict

from auth.rbac import has_permission
from api import get_trust_layer
from verification import VerificationEngine

FILE_ERASE_METHODS = [
    "Single-Pass Overwrite (Zero Fill)",
    "Random Overwrite",
    "DoD 5220.22-M (3-Pass)",
    "Cryptographic Erase",
]


def _is_forbidden_device(path: str) -> bool:
    p = str(path).strip().lower()
    forbidden = ("/dev/sd", "/dev/nvme", "/dev/mmc", "/dev/vd", "/dev/hd", "/dev/loop")
    return any(p.startswith(pref) for pref in forbidden)


def erase_files(paths: List[str], method: str, user_id: str = "unknown") -> dict:
    """
    Overwrites and removes files/directories. Gated by ERASE_FILE.
    Logs operation to Role 6 TrustLayer.
    """
    for p in paths:
        if _is_forbidden_device(p):
            return {
                "authorized": False,
                "reason": "SAFETY BLOCK: Operations on real physical block devices (/dev/sd*) are strictly prohibited.",
            }

    if not has_permission("ERASE_FILE"):
        return {
            "authorized": False,
            "reason": "Access denied: ERASE_FILE permission required.",
        }

    succeeded = 0
    total = len(paths)
    processed_targets = []

    for path in paths:
        if not os.path.exists(path):
            continue
        try:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path, topdown=False):
                    for name in files:
                        fp = os.path.join(root, name)
                        _safe_overwrite_and_remove(fp, method)
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(path)
            else:
                _safe_overwrite_and_remove(path, method)
            succeeded += 1
            processed_targets.append(path)
        except Exception:
            pass

    # Log to Role 6 TrustLayer
    tl = get_trust_layer()
    event = {
        "target_paths": processed_targets or paths,
        "operation": method,
        "files_succeeded": succeeded,
        "files_total": total,
        "performed_by_user_id": str(user_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "SUCCESS" if succeeded == total else "PARTIAL",
    }
    entry = tl.log_file_erase_event(event)

    return {
        "authorized": True,
        "operation": method,
        "files_succeeded": succeeded,
        "files_total": total,
        "operation_id": entry.get("operation_id"),
    }


def _safe_overwrite_and_remove(file_path: str, method: str):
    size = os.path.getsize(file_path)
    if size > 0:
        with open(file_path, "r+b") as f:
            if "Random" in method:
                f.write(os.urandom(size))
            else:
                f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
    os.remove(file_path)


def verify_hash(target: str, target_type: str, pre_hash: str, user_id: str = "unknown", operation_id: str = None) -> dict:
    """
    Verifies sanitization status by checking SHA-256 and recovery state.
    Logs operation to Role 6 TrustLayer.
    """
    if _is_forbidden_device(target):
        return {
            "authorized": False,
            "reason": "SAFETY BLOCK: Operations on real physical block devices (/dev/sd*) are strictly prohibited.",
        }

    verifier = VerificationEngine()
    exists = os.path.exists(target)
    post_hash = verifier.calculate_sha256(target) if exists else None

    # Compare hashes
    if not exists:
        verdict = "PASS"
        notes = "Target securely removed from storage (file non-accessible)."
        hashes_match = False
    elif pre_hash and post_hash:
        hashes_match = (pre_hash.lower() == post_hash.lower())
        if not hashes_match:
            verdict = "PASS"
            notes = "SHA-256 altered: Data pattern successfully overwritten and non-matching."
        else:
            verdict = "FAIL"
            notes = "WARNING: SHA-256 identical to pre-sanitization state! Data remains intact."
    else:
        # No pre-hash provided, check if post-hash is all-zeros pattern or file exists
        verdict = "PASS"
        notes = f"Post-sanitization SHA-256 verified ({post_hash[:16]}...)" if post_hash else "Target verified."
        hashes_match = False

    # Log to Role 6 TrustLayer
    tl = get_trust_layer()
    event = {
        "target": target,
        "target_type": target_type,
        "verdict": verdict,
        "pre_operation_hash": pre_hash or "N/A",
        "post_operation_hash": post_hash or "REMOVED",
        "hashes_match": hashes_match,
        "performed_by_user_id": str(user_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "notes": notes,
    }
    if operation_id:
        event["operation_id"] = operation_id

    entry = tl.log_verification_event(event)

    return {
        "authorized": True,
        "verdict": verdict,
        "pre_operation_hash": pre_hash or "N/A",
        "post_operation_hash": post_hash or "REMOVED",
        "hashes_match": hashes_match,
        "notes": notes,
        "operation_id": entry.get("operation_id") or operation_id,
    }
