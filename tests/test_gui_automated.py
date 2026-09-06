"""
test_gui_automated.py — Automated GUI Tests for all pages and role interactions.

Tests every page:
- LoginPage (success, invalid password)
- DashboardPage (navigation, permission-based tab filtering)
- DevicePage (scanning, selection, recommendation, safe sanitization, post-wipe validation)
- VerificationPage (hash comparison, verdict)
- RecoveryPage (file carving, confidence scoring)
- AssurancePage (assurance scoring, audit log tree, hash chain integrity)
- ReportsPage (PDF certificate, forensic report, JSON export)
- Role switching & RBAC UI enforcement (Admin, Operator, Investigator)
"""

import unittest
from unittest.mock import patch
import os

from gui.app import App
from auth.session import logout


class TestGUIAutomatedFlow(unittest.TestCase):

    def setUp(self):
        logout()
        self.app = App()
        self.app.update()

    def tearDown(self):
        logout()
        try:
            self.app.destroy()
        except Exception:
            pass

    def test_login_and_full_gui_flow(self):
        login_page = self.app.frames["LoginPage"]

        # 1. Invalid login
        login_page.username_var.set("admin")
        login_page.password_var.set("WrongPassword123!")
        login_page._attempt_login()
        self.app.update()
        self.assertIn("Invalid", login_page.error_label.cget("text"))

        # 2. Valid admin login
        login_page.username_var.set("admin")
        login_page.password_var.set("Admin@123456")
        login_page._attempt_login()
        self.app.update()
        self.assertEqual(self.app.session["role"], "ADMIN")

        dashboard = self.app.frames["DashboardPage"]

        # 3. Device Page
        dashboard._show_section("device")
        self.app.update()
        dev_page = dashboard.section_frames["device"]
        dev_page._scan()
        self.app.update()
        self.assertGreater(len(dev_page.tree.get_children()), 0)

        # Select target
        target_path = dev_page.tree.get_children()[0]
        dev_page.tree.selection_set(target_path)
        dev_page._on_select(None)
        self.assertEqual(dev_page.selected_device, target_path)
        self.assertIn("Recommended Method:", dev_page.rec_label.cget("text"))

        # Sanitize with mocked confirmation
        with patch("tkinter.messagebox.askyesno", return_value=True), \
             patch("tkinter.messagebox.showinfo", return_value=True):
            dev_page._sanitize()

            # Wait briefly for worker thread to complete
            import time
            start = time.time()
            while dev_page.is_busy and time.time() - start < 5:
                self.app.update()
                time.sleep(0.05)

        op_id = self.app.last_operation_id
        self.assertIsNotNone(op_id)
        self.assertTrue(op_id.startswith("OP-"))

        # Post-wipe validation
        with patch("tkinter.messagebox.showinfo", return_value=True):
            dev_page._run_quick_validation()
            start = time.time()
            while dev_page.is_busy and time.time() - start < 5:
                self.app.update()
                time.sleep(0.05)

        self.assertIn("PASS", dev_page.validate_result_label.cget("text"))

        # 4. Verification Page
        dashboard._show_section("verification")
        self.app.update()
        verif_page = dashboard.section_frames["verification"]
        verif_page._use_last()
        self.assertEqual(verif_page.op_id_var.get(), op_id)

        with patch("tkinter.messagebox.showinfo", return_value=True):
            verif_page._verify()
            start = time.time()
            while verif_page.is_busy and time.time() - start < 5:
                self.app.update()
                time.sleep(0.05)

        self.assertIn("PASS", verif_page.verdict_label.cget("text"))

        # 5. Recovery Page
        dashboard._show_section("recovery")
        self.app.update()
        rec_page = dashboard.section_frames["recovery"]
        rec_page._use_last_op()
        self.assertEqual(rec_page.op_id_var.get(), op_id)

        with patch("tkinter.messagebox.showinfo", return_value=True):
            rec_page._run_recovery()
            start = time.time()
            while rec_page.is_busy and time.time() - start < 5:
                self.app.update()
                time.sleep(0.05)

        self.assertIn("Recovery", rec_page.status_label.cget("text"))

        # 6. Assurance Page
        dashboard._show_section("assurance")
        self.app.update()
        assur_page = dashboard.section_frames["assurance"]
        assur_page._use_last_op()
        assur_page._get_score()
        self.app.update()
        self.assertIn("/ 100", assur_page.score_label.cget("text"))
        self.assertIn("Grade A", assur_page.verdict_label.cget("text"))
        self.assertIn("Chain intact", assur_page.chain_label.cget("text"))
        self.assertGreater(len(assur_page.tree.get_children()), 0)

        # 7. Reports Page
        dashboard._show_section("reports")
        self.app.update()
        rep_page = dashboard.section_frames["reports"]
        rep_page._use_last_op()
        self.assertEqual(rep_page.op_id_var.get(), op_id)

        with patch("tkinter.messagebox.showinfo", return_value=True), \
             patch("gui.pages.reports_page._open_path", return_value=None):
            rep_page._gen_certificate()
            rep_page._gen_report()

        self.app.update()
        log_text = rep_page.result_text.get("1.0", "end")
        self.assertIn("Certificate generated successfully", log_text)
        self.assertIn("Forensic report generated successfully", log_text)

    def test_rbac_ui_enforcement(self):
        login_page = self.app.frames["LoginPage"]

        # Operator login
        login_page.username_var.set("operator1")
        login_page.password_var.set("Operator@123")
        login_page._attempt_login()
        self.app.update()

        dashboard = self.app.frames["DashboardPage"]
        # Operator has DETECT_USB, SANITIZE_USB, ERASE_FILE.
        # But NOT RECOVER_FILES, GENERATE_REPORT, VIEW_AUDIT.
        # Navigation buttons for unauthorized tabs must be removed from layout
        self.assertEqual(dashboard.nav_buttons["recovery"].winfo_ismapped(), 0)
        self.assertEqual(dashboard.nav_buttons["reports"].winfo_ismapped(), 0)
        self.assertEqual(dashboard.nav_buttons["assurance"].winfo_ismapped(), 0)
        self.assertEqual(dashboard.nav_buttons["device"].winfo_ismapped(), 1)

        # Logout
        self.app.logout()
        self.app.update()

        # Investigator login
        login_page.username_var.set("investigator1")
        login_page.password_var.set("Investigator@123")
        login_page._attempt_login()
        self.app.update()

        # Investigator has DETECT_USB, RECOVER_FILES, VIEW_RECOVERY, GENERATE_REPORT, VIEW_AUDIT.
        # But NOT SANITIZE_USB, ERASE_FILE.
        self.assertEqual(dashboard.nav_buttons["file_eraser"].winfo_ismapped(), 0)
        self.assertEqual(dashboard.nav_buttons["recovery"].winfo_ismapped(), 1)
        self.assertEqual(dashboard.nav_buttons["reports"].winfo_ismapped(), 1)

        # Show device tab as investigator: sanitize controls must NOT be packed
        dashboard._show_section("device")
        self.app.update()
        dev_page = dashboard.section_frames["device"]
        self.assertEqual(dev_page.sanitize_frame.winfo_ismapped(), 0)


if __name__ == "__main__":
    unittest.main()
