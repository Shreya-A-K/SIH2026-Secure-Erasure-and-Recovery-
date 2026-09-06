"""
Role 3 - Device Detection & Sanitization Engine
=================================================
NO INTEGRATION SPEC WAS PROVIDED FOR THIS ROLE. Person 1's PROPOSED
interface, shaped to match exactly what Role6_API_Contract.docx says
Role 3 must send to Role 6 (log_device_event / log_sanitization_event
payloads) - so at minimum the OUTPUT shapes below are already correct.
The function names/inputs are Person 1's suggestion - confirm with
Person 3.
"""

import uuid
from datetime import datetime, timezone

from backend import role6_trust
from backend.auth.rbac import has_permission

SANITIZATION_METHODS = ["ZEROS", "RANDOM", "DOD_3_PASS", "DOD_7_PASS", "GUTMANN_35"]


def detect_devices() -> list:
    """STUB: returns fake removable devices. Person 3: replace with
    real OS-level enumeration (e.g. via psutil / lsblk / pyudev).
    Gated on DETECT_USB per Role2.docx - ADMIN, OPERATOR, and
    INVESTIGATOR all have this permission."""
    if not has_permission("DETECT_USB"):
        return []
    return [
        {"device_path": "/dev/sdb", "serial": "SN-20240912-USB", "model": "SanDisk Ultra 32GB",
         "capacity_gb": 32.0, "filesystem": "FAT32", "is_removable": True},
        {"device_path": "/dev/sdc", "serial": "SN-20240913-USB", "model": "Kingston DataTraveler 16GB",
         "capacity_gb": 16.0, "filesystem": "exFAT", "is_removable": True},
    ]


def get_device_details(device_path: str) -> dict:
    if not has_permission("DETECT_USB"):
        return {}
    for d in detect_devices():
        if d["device_path"] == device_path:
            role6_trust.log_device_event({
                "event_type": "DEVICE_DETECTED", **d,
                "detected_by_user_id": "unknown",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return d
    return {}


def sanitize_device(device_path: str, method: str, user_id: str) -> dict:
    """STUB: pretends to wipe instantly. Person 3: replace with the
    real overwrite/DoD/Gutmann implementation - keep this return shape,
    it matches what Role 6 needs verbatim. Gated on SANITIZE_USB per
    Role2.docx - ADMIN and OPERATOR only."""
    if not has_permission("SANITIZE_USB"):
        return {"authorized": False, "reason": "Access denied: SANITIZE_USB permission required."}

    operation_id = f"OP-{uuid.uuid4().hex[:8].upper()}"
    start = datetime.now(timezone.utc)
    device = next((d for d in detect_devices() if d["device_path"] == device_path), {})

    event = {
        "event_type": "SANITIZATION_COMPLETE",
        "operation_id": operation_id,  # extra field, not in original Role6 spec table -
                                        # added so Role 6 can correlate events by operation_id
                                        # instead of only device_path. Confirm with Person 6/3.
        "device_path": device_path,
        "serial": device.get("serial", "UNKNOWN"),
        "method": method,
        "passes_completed": 3 if "3_PASS" in method else 1,
        "sectors_wiped": int((device.get("capacity_gb", 0) or 0) * 1_000_000),
        "capacity_gb": device.get("capacity_gb", 0),
        "status": "SUCCESS",
        "start_time": start.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": 1,
        "performed_by_user_id": user_id,
        "notes": "[STUB] simulated wipe",
    }
    role6_trust.log_sanitization_event(event)

    return {"operation_id": operation_id, "device_path": device_path, "method": method,
            "sanitization_status": "SUCCESS"}
