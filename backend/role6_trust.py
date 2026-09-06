"""
Role 6 - Trust Layer (Audit / Assurance / Certificates)
========================================================
STUB IMPLEMENTATION - built by Person 1 (GUI) so the GUI is testable
before Person 6's real module is ready.

Person 6: replace the body of every function below with your real
SQLite-backed implementation. DO NOT change any function name or
signature - Person 1's GUI code calls these exact names.

Contract source: Role6_API_Contract.docx (uploaded by Roshini's team).
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from backend.auth.rbac import has_permission

# ---------------------------------------------------------------------------
# In-memory "hash chain" audit log (stands in for the real SQLite audit_log
# table + hash chain until Person 6's module is ready). Each entry's hash is
# derived from its own content + the previous entry's hash, so any tampering
# breaks the chain - this mirrors the real tamper-evidence requirement.
# ---------------------------------------------------------------------------
_AUDIT_LOG = []          # list[dict] - append-only
_OPERATIONS = {}         # operation_id -> aggregated info used for scoring


def _now():
    return datetime.now(timezone.utc).isoformat()


def _chain_append(event_type, summary, payload):
    prev_hash = _AUDIT_LOG[-1]["hash"] if _AUDIT_LOG else "0" * 64
    seq = len(_AUDIT_LOG) + 1
    ts = _now()
    block = json.dumps(
        {"seq": seq, "event_type": event_type, "payload": payload,
         "timestamp": ts, "prev_hash": prev_hash},
        sort_keys=True, default=str,
    )
    this_hash = hashlib.sha256(block.encode()).hexdigest()
    entry = {
        "log_id": seq,
        "sequence": seq,
        "event_type": event_type,
        "summary": summary,
        "timestamp": ts,
        "hash": this_hash,
        "prev_hash": prev_hash,
        "chain_valid": True,
        "payload": payload,
    }
    _AUDIT_LOG.append(entry)
    return entry


def _touch_operation(operation_id, **fields):
    op = _OPERATIONS.setdefault(operation_id, {})
    op.update(fields)
    return op


# ---------------------------------------------------------------------------
# INPUTS - called by Roles 2, 3, 4, 5
# ---------------------------------------------------------------------------

def log_auth_event(event: dict):
    """Role 2 calls this on every login / logout / permission denial."""
    summary = f"{event.get('sub_type')} - {event.get('username')} ({event.get('role')})"
    return _chain_append("AUTH_EVENT", summary, event)


def log_device_event(event: dict):
    """Role 3 calls this when a device is detected."""
    summary = f"Device detected: {event.get('model')} ({event.get('device_path')})"
    return _chain_append("DEVICE_DETECTED", summary, event)


def log_sanitization_event(event: dict):
    """Role 3 calls this when a wipe operation completes."""
    op_id = event.get("operation_id") or event.get("device_path")
    _touch_operation(op_id, sanitization=event)
    summary = f"{event.get('method')} wipe on {event.get('device_path')} - {event.get('status')}"
    return _chain_append("SANITIZATION_COMPLETE", summary, event)


def log_file_erase_event(event: dict):
    """Role 4 calls this when a file/folder erase completes."""
    summary = f"{event.get('operation')} erase - {event.get('files_succeeded')}/{event.get('files_total')} succeeded"
    return _chain_append("FILE_ERASE_COMPLETE", summary, event)


def log_verification_event(event: dict):
    """Role 4 calls this when SHA-256 verification completes."""
    op_id = event.get("operation_id") or event.get("target")
    _touch_operation(op_id, verification=event)
    summary = f"Verification {event.get('verdict')} on {event.get('target')}"
    return _chain_append("VERIFICATION_COMPLETE", summary, event)


def log_recovery_validation_event(event: dict):
    """Role 5 calls this (via to_audit_event) after post-wipe validation."""
    op_id = event.get("operation_id") or event.get("device_path")
    _touch_operation(op_id, recovery_validation=event)
    summary = f"Post-wipe validation {event.get('verdict')} on {event.get('device_path')}"
    return _chain_append("POST_WIPE_VALIDATION", summary, event)


# ---------------------------------------------------------------------------
# OUTPUTS - called by Role 1 (GUI)
# ---------------------------------------------------------------------------

_GRADE_TABLE = [
    (90, 101, "A+", "CERTIFIED SECURE"),
    (75, 90, "A", "HIGH ASSURANCE"),
    (60, 75, "B", "MODERATE ASSURANCE"),
    (40, 60, "C", "LOW ASSURANCE"),
    (0, 40, "F", "FAILED / UNRELIABLE"),
]


def _grade_for(score):
    for lo, hi, grade, verdict in _GRADE_TABLE:
        if lo <= score < hi:
            return grade, verdict
    return "F", "FAILED / UNRELIABLE"


def get_assurance_score(operation_id: str) -> dict:
    """Returns the assurance score breakdown for an operation.
    STUB: computes a score from whatever has been logged for this
    operation_id so far; Person 6's real version reads from SQLite.
    Gated on VIEW_AUDIT per Role2.docx (assumption - the doc doesn't
    name a permission specifically for assurance scores; confirm with
    Person 2/6).
    """
    if not has_permission("VIEW_AUDIT"):
        return {
            "operation_id": operation_id, "score": 0, "grade": "-", "verdict": "ACCESS DENIED",
            "breakdown": {"sanitization_method_score": 0, "verification_passed": 0,
                          "recovery_validation_passed": 0, "audit_chain_intact": 0},
            "max_score": 100, "generated_at": _now(), "authorized": False,
        }

    op = _OPERATIONS.get(operation_id, {})

    method_score = 30 if op.get("sanitization", {}).get("status") == "SUCCESS" else 0
    verification_score = 25 if op.get("verification", {}).get("verdict") == "PASS" else 0
    recovery_score = 25 if op.get("recovery_validation", {}).get("verdict") == "PASS" else 0
    chain_score = 7 if verify_chain_integrity()["chain_intact"] else 0

    total = method_score + verification_score + recovery_score + chain_score
    grade, verdict = _grade_for(total)

    return {
        "operation_id": operation_id,
        "score": total,
        "grade": grade,
        "verdict": verdict,
        "breakdown": {
            "sanitization_method_score": method_score,
            "verification_passed": verification_score,
            "recovery_validation_passed": recovery_score,
            "audit_chain_intact": chain_score,
        },
        "max_score": 100,
        "generated_at": _now(),
    }


def get_audit_log(limit: int = 50, filter_event_type=None) -> list:
    if not has_permission("VIEW_AUDIT"):
        return []
    entries = _AUDIT_LOG
    if filter_event_type:
        entries = [e for e in entries if e["event_type"] == filter_event_type]
    # newest first, like a real log viewer
    return list(reversed(entries[-limit:]))


def verify_chain_integrity() -> dict:
    if not has_permission("VIEW_AUDIT"):
        return {"total_entries": 0, "chain_intact": False, "first_broken_at_sequence": None,
                "verified_at": _now(), "authorized": False}

    prev = "0" * 64
    for i, entry in enumerate(_AUDIT_LOG):
        if entry["prev_hash"] != prev:
            return {
                "total_entries": len(_AUDIT_LOG),
                "chain_intact": False,
                "first_broken_at_sequence": entry["sequence"],
                "verified_at": _now(),
            }
        prev = entry["hash"]
    return {
        "total_entries": len(_AUDIT_LOG),
        "chain_intact": True,
        "first_broken_at_sequence": None,
        "verified_at": _now(),
    }


def _ensure_reports_dir():
    path = os.path.join(os.path.expanduser("~"), "SIH", "reports")
    os.makedirs(path, exist_ok=True)
    return path


def generate_certificate(operation_id: str) -> str:
    """STUB: writes a plain-text placeholder instead of a real PDF.
    Person 6: replace with real PDF generation (e.g. reportlab), same
    function name/signature, returning the absolute path. Gated on
    GENERATE_REPORT per Role2.docx - ADMIN and INVESTIGATOR only.
    """
    if not has_permission("GENERATE_REPORT"):
        return None

    reports_dir = _ensure_reports_dir()
    path = os.path.join(reports_dir, f"CERT-{operation_id}.pdf")
    score = get_assurance_score(operation_id)
    with open(path, "w") as f:
        f.write(f"[STUB CERTIFICATE]\nOperation: {operation_id}\n"
                 f"Score: {score['score']} ({score['grade']}) - {score['verdict']}\n"
                 f"Generated: {_now()}\n")
    return path


def generate_forensic_report(operation_id: str) -> str:
    """STUB - see generate_certificate() notes. Gated on GENERATE_REPORT."""
    if not has_permission("GENERATE_REPORT"):
        return None

    reports_dir = _ensure_reports_dir()
    path = os.path.join(reports_dir, f"REPORT-{operation_id}.pdf")
    with open(path, "w") as f:
        f.write(f"[STUB FORENSIC REPORT]\nOperation: {operation_id}\n"
                 f"Audit entries: {len(_AUDIT_LOG)}\nGenerated: {_now()}\n")
    return path


def export_audit_log_json(output_path: str) -> bool:
    if not has_permission("VIEW_AUDIT"):
        return False
    try:
        with open(output_path, "w") as f:
            json.dump(_AUDIT_LOG, f, indent=2, default=str)
        return True
    except OSError:
        return False
