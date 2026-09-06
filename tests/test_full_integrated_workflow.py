"""
test_full_integrated_workflow.py — Full Pipeline Integration Tests for SIH 26149.

Validates the complete 15-step target flow:
LOGIN -> RBAC -> DETECTION -> INFO -> RECOMMENDATION -> SANITIZATION ->
VERIFICATION -> POST-WIPE VALIDATION -> FORENSIC RECOVERY ->
CONFIDENCE SCORE -> AUDIT LOG -> HASH CHAIN -> ASSURANCE SCORE ->
CERTIFICATE -> FORENSIC REPORT.

Also validates all error cases:
- Wrong password
- Permission denied
- Physical device safety block (/dev/sdX)
- Missing target file
- Invalid operation ID
"""

import os
import unittest
import tempfile
import shutil
from pathlib import Path

from auth.login import authenticate
from auth.session import login_user, logout, get_current_user
from auth.rbac import has_permission
from database.setup_database import init_database
import role3_sanitization
import role4_file_ops
from person5_final.post_wipe_validation import run_post_wipe_scan, to_audit_event
from person5_final.recovery_engine import run_full_recovery
from api import get_trust_layer


class TestFullIntegratedPlatform(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_database(seed_defaults=True)
        cls.tl = get_trust_layer()

    def setUp(self):
        logout()
        self.test_dir = tempfile.mkdtemp(prefix="sih_test_")
        self.test_target = os.path.join(self.test_dir, "confidential_test.bin")
        with open(self.test_target, "wb") as f:
            f.write(b"TOP_SECRET_SIH_CYBER_FORENSIC_TARGET_DATA\n" * 50)

    def tearDown(self):
        logout()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_01_authentication_and_rbac(self):
        # 1. Failed login with wrong password
        failed_user = authenticate("admin", "WrongPassword!999")
        self.assertIsNone(failed_user)

        # 2. Successful Admin login
        admin = authenticate("admin", "Admin@123456")
        self.assertIsNotNone(admin)
        self.assertEqual(admin["role"], "ADMIN")
        login_user(admin)
        self.assertEqual(get_current_user()["username"], "admin")

        # Admin permissions
        self.assertTrue(has_permission("DETECT_USB"))
        self.assertTrue(has_permission("SANITIZE_USB"))
        self.assertTrue(has_permission("ERASE_FILE"))
        self.assertTrue(has_permission("RECOVER_FILES"))
        self.assertTrue(has_permission("VIEW_RECOVERY"))
        self.assertTrue(has_permission("GENERATE_REPORT"))
        self.assertTrue(has_permission("VIEW_AUDIT"))

        logout()

        # 3. Operator login
        op = authenticate("operator1", "Operator@123")
        self.assertIsNotNone(op)
        self.assertEqual(op["role"], "OPERATOR")
        login_user(op)
        self.assertTrue(has_permission("SANITIZE_USB"))
        self.assertFalse(has_permission("GENERATE_REPORT"))
        self.assertFalse(has_permission("RECOVER_FILES"))

        logout()

        # 4. Investigator login
        inv = authenticate("investigator1", "Investigator@123")
        self.assertIsNotNone(inv)
        self.assertEqual(inv["role"], "INVESTIGATOR")
        login_user(inv)
        self.assertFalse(has_permission("SANITIZE_USB"))
        self.assertTrue(has_permission("RECOVER_FILES"))
        self.assertTrue(has_permission("GENERATE_REPORT"))

    def test_02_safety_guards(self):
        # Even Admin cannot sanitize physical block devices
        admin = authenticate("admin", "Admin@123456")
        login_user(admin)

        for dev in ("/dev/sda", "/dev/sdb1", "/dev/nvme0n1", "/dev/mmcblk0"):
            res = role3_sanitization.sanitize_device(dev, "Single-Pass Overwrite (Zero Fill)", "admin")
            self.assertFalse(res["authorized"])
            self.assertIn("SAFETY BLOCK", res["reason"])

            erase_res = role4_file_ops.erase_files([dev], "Single-Pass Overwrite (Zero Fill)", "admin")
            self.assertFalse(erase_res["authorized"])

    def test_03_device_detection_and_recommendation(self):
        admin = authenticate("admin", "Admin@123456")
        login_user(admin)

        devices = role3_sanitization.detect_devices()
        self.assertGreater(len(devices), 0)
        for d in devices:
            self.assertIn("device_path", d)
            self.assertIn("model", d)
            self.assertIn("capacity_gb", d)
            rec = role3_sanitization.recommend_method(d["device_path"])
            self.assertIn(rec, role3_sanitization.SANITIZATION_METHODS)

    def test_04_complete_end_to_end_pipeline(self):
        # Step 1: Login as Admin
        admin = authenticate("admin", "Admin@123456")
        login_user(admin)

        # Step 2: Detection and Info
        devices = role3_sanitization.detect_devices()
        target_path = self.test_target
        rec_method = role3_sanitization.recommend_method(target_path)

        # Step 3: Safe Sanitization
        pre_hash = self.tl.conn.execute("SELECT 1").fetchone() # DB check
        san_res = role3_sanitization.sanitize_device(
            target_path, "DoD 5220.22-M (3-Pass)", admin["username"]
        )
        self.assertTrue(san_res["authorized"])
        self.assertEqual(san_res["status"], "SUCCESS")
        op_id = san_res["operation_id"]
        self.assertTrue(op_id.startswith("OP-"))
        self.assertNotEqual(san_res["pre_hash"], san_res["post_hash"])

        # Step 4: Verification (Role 4)
        verif_res = role4_file_ops.verify_hash(
            target=target_path,
            target_type="FILE",
            pre_hash=san_res["pre_hash"],
            user_id=admin["username"],
            operation_id=op_id,
        )
        self.assertTrue(verif_res["authorized"])
        self.assertEqual(verif_res["verdict"], "PASS")
        self.assertFalse(verif_res["hashes_match"])

        # Step 5: Post-Wipe Forensic Validation (Role 5)
        val_req = {
            "operation_id": op_id,
            "device_path": target_path,
            "sanitization_status": "SUCCESS",
            "method": "OVERWRITE",
        }
        val_res = run_post_wipe_scan(val_req)
        self.assertEqual(val_res["validation_status"], "PASS")
        self.assertEqual(val_res["qualifying_artifacts"], 0)

        audit_ev = to_audit_event(val_res)
        audit_ev["operation_id"] = op_id
        self.tl.log_recovery_validation_event(audit_ev)

        # Step 6: Deep Recovery Scan (Role 5)
        rec_req = {
            "operation_id": op_id,
            "device_path": target_path,
            "scan_type": "QUICK",
            "output_dir": os.path.join(self.test_dir, "recovered"),
        }
        rec_res = run_full_recovery(rec_req)
        self.assertEqual(rec_res["status"], "SUCCESS")

        # Step 7: Audit Log & Hash Chain Integrity (Role 6)
        chain_res = self.tl.verify_chain_integrity()
        self.assertTrue(chain_res["chain_intact"])
        self.assertGreater(chain_res["total_entries"], 0)

        # Step 8: Assurance Score (Role 6)
        score_res = self.tl.get_assurance_score(op_id)
        self.assertEqual(score_res["operation_id"], op_id)
        self.assertGreaterEqual(score_res["score"], 80)
        self.assertIn(score_res["grade"], ["A", "A+"])
        self.assertEqual(score_res["breakdown"]["verification_passed"], 25)
        self.assertEqual(score_res["breakdown"]["recovery_validation_passed"], 25)
        self.assertEqual(score_res["breakdown"]["audit_chain_intact"], 20)

        # Step 9: Certificate Generation (Role 6)
        cert_path = self.tl.generate_certificate(op_id)
        self.assertTrue(os.path.exists(cert_path))
        self.assertTrue(cert_path.endswith(".pdf"))
        self.assertGreater(os.path.getsize(cert_path), 0)

        # Step 10: Forensic Report Generation (Role 6)
        report_path = self.tl.generate_forensic_report(op_id)
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(report_path.endswith(".pdf"))
        self.assertGreater(os.path.getsize(report_path), 0)

        # Step 11: JSON Audit Export
        json_path = os.path.join(self.test_dir, "audit_export.json")
        export_ok = self.tl.export_audit_log_json(json_path)
        self.assertTrue(export_ok)
        self.assertTrue(os.path.exists(json_path))
        self.assertGreater(os.path.getsize(json_path), 0)

    def test_05_error_cases(self):
        # 1. Operator cannot generate report
        op = authenticate("operator1", "Operator@123")
        login_user(op)
        self.assertFalse(has_permission("GENERATE_REPORT"))

        # 2. Investigator cannot sanitize
        logout()
        inv = authenticate("investigator1", "Investigator@123")
        login_user(inv)
        res = role3_sanitization.sanitize_device(self.test_target, "NIST 800-88 Clear", inv["username"])
        self.assertFalse(res["authorized"])
        self.assertIn("Access denied", res["reason"])

        # 3. Missing target
        logout()
        admin = authenticate("admin", "Admin@123456")
        login_user(admin)
        res_missing = role3_sanitization.sanitize_device("/nonexistent/file.txt", "Random Overwrite", admin["username"])
        self.assertEqual(res_missing["status"], "FAILURE")
        self.assertIn("Target not found", res_missing["reason"])

        # 4. Invalid operation ID in assurance score
        with self.assertRaises(ValueError):
            self.tl.get_assurance_score("OP-INVALID-999999")


if __name__ == "__main__":
    unittest.main()
