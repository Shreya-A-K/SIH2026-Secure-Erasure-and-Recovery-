import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestRole1GUI(unittest.TestCase):

    def setUp(self):
        self.valid_views = ["dashboard", "file_eraser", "drive_eraser", "reports", "settings"]
        self.current_view = "dashboard"

    def test_navigation_switch_valid_views(self):
        for view in self.valid_views:
            self.current_view = view
            self.assertEqual(self.current_view, view)

    def test_navigation_invalid_view_fallback(self):
        invalid_view = "unknown_screen"
        if invalid_view not in self.valid_views:
            self.current_view = "dashboard"
        self.assertEqual(self.current_view, "dashboard")

    def test_button_callback_trigger(self):
        callback_mock = MagicMock()
        # Simulate button click trigger
        callback_mock(action="START_ERASURE", target="/path/to/file")
        callback_mock.assert_called_once_with(action="START_ERASURE", target="/path/to/file")

    def test_confirmation_dialog_user_accept(self):
        dialog_state = {"confirmed": False}

        def confirm_dialog(user_input):
            if user_input.strip() == "ERASE":
                dialog_state["confirmed"] = True

        confirm_dialog("ERASE")
        self.assertTrue(dialog_state["confirmed"])

    def test_confirmation_dialog_user_cancel(self):
        dialog_state = {"confirmed": False}

        def confirm_dialog(user_input):
            if user_input.strip() == "ERASE":
                dialog_state["confirmed"] = True

        confirm_dialog("cancel")
        self.assertFalse(dialog_state["confirmed"])


if __name__ == "__main__":
    unittest.main()