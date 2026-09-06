"""
role3_sanitization.py — Role 3 Adapter for Sanitization Engine.

Safely manages virtual test targets and sanitization operations.
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

SANITIZATION_METHODS = [
    "Single-Pass Overwrite (Zero Fill)",
    "Random Overwrite",
    "DoD 5220.22-M (3-Pass)",
    "NIST 800-88 Clear",
]

BASE_DIR = Path(__file__).resolve().parent


def _is_forbidden_device(path: str) -> bool:
    p = str(path).strip().lower()
    forbidden = ("/dev/sd", "/dev/nvme", "/dev/mmc", "/dev/vd", "/dev/hd", "/dev/loop")
    return any(p.startswith(pref) for pref in forbidden)


def detect_devices() -> List[Dict]:
    """
    Scans for safe test targets in test_data/.
    NEVER queries physical block devices.
    Logs DEVICE_DETECTED events to the TrustLayer.
    """
    test_dir = BASE_DIR / "test_data"
    test_dir.mkdir(parents=True, exist_ok=True)

    img_path = test_dir / "test.img"
    if not img_path.exists() or img_path.stat().st_size == 0:
        with open(img_path, "wb") as f:
            f.write(b"CONFIDENTIAL_DISK_BLOCK_DATA_SIH26149\n" * 500)

    txt_path = test_dir / "test_data.txt"
    if not txt_path.exists() or txt_path.stat().st_size == 0:
        with open(txt_path, "wb") as f:
            f.write(b"TOP SECRET SANITIZATION TARGET FILE - SIH 26149\n" * 20)

    targets = [
        (str(img_path), "Virtual Demo Disk Image (Safe)", "RAW/EXT4", "VIRT-DISK-001"),
        (str(txt_path), "Confidential Target Document", "TXT", "VIRT-DOC-002"),
    ]

    tl = get_trust_layer()
    now = datetime.now(timezone.utc).isoformat()
    devices = []

    for path_str, model, fs, serial in targets:
        size_bytes = os.path.getsize(path_str) if os.path.exists(path_str) else 0
        cap_gb = f"{size_bytes / (1024**3):.4f}" if size_bytes > 0 else "0.001"
        dev_info = {
            "device_path": path_str,
            "model": model,
            "capacity_gb": cap_gb,
            "filesystem": fs,
            "serial": serial,
            "is_removable": True,
            "timestamp": now,
        }
        try:
            tl.log_device_event(dev_info)
        except Exception:
            pass
        devices.append(dev_info)

    return devices


def recommend_method(device_path: str) -> str:
    """Recommends an appropriate sanitization standard based on device type."""
    if str(device_path).endswith(".img"):
        return "NIST 800-88 Clear"
    return "Single-Pass Overwrite (Zero Fill)"


def sanitize_device(device_path: str, method: str, user_id: str = "unknown", operation_id: str = None) -> dict:
    """
    Safely sanitizes the target test file.
    Enforces RBAC (SANITIZE_USB) and blocks physical devices.
    Logs operation to Role 6 TrustLayer.
    """
    if _is_forbidden_device(device_path):
        return {
            "authorized": False,
            "status": "FAILURE",
            "sanitization_status": "FAILURE",
            "reason": "SAFETY BLOCK: Operations on real physical block devices (/dev/sd*) are strictly prohibited.",
        }

    if not has_permission("SANITIZE_USB"):
        return {
            "authorized": False,
            "status": "FAILURE",
            "sanitization_status": "FAILURE",
            "reason": "Access denied: SANITIZE_USB permission required.",
        }

    if not os.path.exists(device_path):
        return {
            "authorized": True,
            "status": "FAILURE",
            "sanitization_status": "FAILURE",
            "reason": f"Target not found: {device_path}",
        }

    start_time = datetime.now(timezone.utc).isoformat()
    file_size = os.path.getsize(device_path)

    verifier = VerificationEngine()
    pre_hash = verifier.calculate_sha256(device_path) or "HASH_UNAVAILABLE"

    # Perform safe wipe on test file
    try:
        with open(device_path, "r+b") as f:
            if "DoD" in method:
                # Pass 1: zeroes
                f.seek(0)
                f.write(b"\x00" * file_size)
                f.flush()
                # Pass 2: ones
                f.seek(0)
                f.write(b"\xff" * file_size)
                f.flush()
                # Pass 3: zeroes
                f.seek(0)
                f.write(b"\x00" * file_size)
                f.flush()
            elif "Random" in method:
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
            else:
                f.seek(0)
                f.write(b"\x00" * file_size)
                f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        return {
            "authorized": True,
            "status": "FAILURE",
            "sanitization_status": "FAILURE",
            "reason": f"Sanitization error: {e}",
        }

    end_time = datetime.now(timezone.utc).isoformat()
    post_hash = verifier.calculate_sha256(device_path) or "HASH_UNAVAILABLE"

    # Log to Role 6 TrustLayer
    tl = get_trust_layer()
    event = {
        "device_path": device_path,
        "method": method,
        "status": "SUCCESS",
        "performed_by_user_id": str(user_id),
        "start_time": start_time,
        "end_time": end_time,
        "pre_hash": pre_hash,
        "post_hash": post_hash,
    }
    if operation_id:
        event["operation_id"] = operation_id

    entry = tl.log_sanitization_event(event)
    op_id = entry.get("operation_id")

    return {
        "authorized": True,
        "status": "SUCCESS",
        "sanitization_status": "SUCCESS",
        "operation_id": op_id,
        "device_path": device_path,
        "method": method,
        "pre_hash": pre_hash,
        "post_hash": post_hash,
        "start_time": start_time,
        "end_time": end_time,
        "message": f"Successfully sanitized {device_path} using {method}.",
    }
