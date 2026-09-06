"""
demo.py — Simulates Roles 2, 3, 4, 5 calling into your Role 6 Trust Layer,
so you can prove the whole module works BEFORE the GUI (Role 1) exists.

Run: python3 -m role6_trust_layer.demo
"""

import os
from datetime import datetime, timezone
import db
from api import TrustLayer

TEST_DB = os.path.join(os.path.dirname(__file__), "demo_trust_layer.db")


def now():
    return datetime.now(timezone.utc).isoformat()


def run_demo():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

    tl = TrustLayer(db_path=TEST_DB)

    print("=" * 70)
    print("STEP 1 — Role 2 logs a successful login")
    print("=" * 70)
    tl.log_auth_event({
        "event_type": "AUTH_EVENT", "sub_type": "LOGIN_SUCCESS",
        "user_id": "operator_01", "username": "john_doe", "role": "OPERATOR",
        "timestamp": now(), "notes": "",
    })

    print("\n" + "=" * 70)
    print("STEP 2 — Role 3 detects a USB device")
    print("=" * 70)
    tl.log_device_event({
        "event_type": "DEVICE_DETECTED", "device_path": "/dev/sdb",
        "serial": "SN-DEMO-USB01", "model": "SanDisk Ultra 32GB",
        "capacity_gb": 32.0, "filesystem": "FAT32", "is_removable": True,
        "detected_by_user_id": "operator_01", "timestamp": now(),
    })

    print("\n" + "=" * 70)
    print("STEP 3 — Role 3 completes a DoD 3-pass wipe (opens an operation)")
    print("=" * 70)
    result = tl.log_sanitization_event({
        "event_type": "SANITIZATION_COMPLETE", "device_path": "/dev/sdb",
        "serial": "SN-DEMO-USB01", "method": "DOD_3_PASS", "passes_completed": 3,
        "sectors_wiped": 62521344, "capacity_gb": 32.0, "status": "SUCCESS",
        "start_time": now(), "end_time": now(), "duration_seconds": 780,
        "performed_by_user_id": "operator_01", "notes": "",
    })
    op_id = result["operation_id"]
    print(f"--> Operation opened: {op_id}")

    print("\n" + "=" * 70)
    print("STEP 4 — Role 4 confirms SHA-256 verification (hashes differ = wipe worked)")
    print("=" * 70)
    tl.log_verification_event({
        "event_type": "VERIFICATION_COMPLETE", "target": "/dev/sdb", "target_type": "DEVICE",
        "pre_operation_hash": "a3f1c2d4...", "post_operation_hash": "00000000...",
        "hashes_match": False, "verdict": "PASS", "verified_by_user_id": "operator_01",
        "timestamp": now(), "notes": "Hashes differ - confirms wipe altered data as expected.",
    })

    print("\n" + "=" * 70)
    print("STEP 5 — Role 5 runs post-wipe recovery validation (nothing recoverable)")
    print("=" * 70)
    tl.log_recovery_validation_event({
        "event_type": "POST_WIPE_VALIDATION", "device_path": "/dev/sdb", "verdict": "PASS",
        "scope": "full", "artifacts_found": 0, "qualifying_artifacts": 0,
        "evidence_hashes": [], "timestamp": now(), "notes": "No artifacts scored >= 40 confidence.",
    })

    print("\n" + "=" * 70)
    print("STEP 6 — Role 6 (you) computes the assurance score")
    print("=" * 70)
    score = tl.get_assurance_score(op_id)
    print(f"Score: {score['score']}/100 | Grade: {score['grade']} | Verdict: {score['verdict']}")
    print(f"Breakdown: {score['breakdown']}")

    print("\n" + "=" * 70)
    print("STEP 7 — Verify hash chain integrity")
    print("=" * 70)
    chain_status = tl.verify_chain_integrity()
    print(chain_status)

    print("\n" + "=" * 70)
    print("STEP 8 — Generate certificate + forensic report PDFs")
    print("=" * 70)
    cert_path = tl.generate_certificate(op_id)
    report_path = tl.generate_forensic_report(op_id)
    print(f"Certificate: {cert_path}")
    print(f"Forensic Report: {report_path}")

    print("\n" + "=" * 70)
    print("STEP 9 — Export audit log to JSON")
    print("=" * 70)
    export_path = os.path.join(os.path.dirname(__file__), "demo_audit_export.json")
    ok = tl.export_audit_log_json(export_path)
    print(f"Export success: {ok} -> {export_path}")

    print("\n" + "=" * 70)
    print("STEP 10 — Simulate tampering, then re-verify chain (should now FAIL)")
    print("=" * 70)
    tl.conn.execute("UPDATE audit_log SET payload_json = '{\"tampered\":true}' WHERE sequence = 2")
    tl.conn.commit()
    tampered_status = tl.verify_chain_integrity()
    print(tampered_status)

    print("\nDone. Return codes above prove: hash chain works, tampering is detected,")
    print("scoring works, PDFs generate, JSON export works — all without any GUI.")


if __name__ == "__main__":
    run_demo()

