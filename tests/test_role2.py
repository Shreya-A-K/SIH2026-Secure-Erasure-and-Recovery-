import unittest
import hashlib
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestRole2Auth(unittest.TestCase):

    def setUp(self):
        self.users_db = {
            "admin": {
                "hash": hashlib.sha256(b"AdminPass123!").hexdigest(),
                "role": "ADMIN"
            },
            "operator": {
                "hash": hashlib.sha256(b"OpPass123!").hexdigest(),
                "role": "OPERATOR"
            },
            "auditor": {
                "hash": hashlib.sha256(b"AuditPass123!").hexdigest(),
                "role": "AUDITOR"
            }
        }
        self.rbac_permissions = {
            "ADMIN": ["wipe_file", "wipe_drive", "view_reports", "manage_users"],
            "OPERATOR": ["wipe_file", "view_reports"],
            "AUDITOR": ["view_reports"]
        }

    def authenticate(self, username, password):
        user = self.users_db.get(username)
        if not user:
            return None, "USER_NOT_FOUND"
        
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        if user["hash"] == pwd_hash:
            return user["role"], "SUCCESS"
        return None, "INVALID_PASSWORD"

    def has_permission(self, role, action):
        return action in self.rbac_permissions.get(role, [])

    def test_successful_authentication(self):
        role, status = self.authenticate("admin", "AdminPass123!")
        self.assertEqual(status, "SUCCESS")
        self.assertEqual(role, "ADMIN")

    def test_failed_authentication_bad_password(self):
        role, status = self.authenticate("admin", "WrongPassword")
        self.assertEqual(status, "INVALID_PASSWORD")
        self.assertIsNone(role)

    def test_failed_authentication_unknown_user(self):
        role, status = self.authenticate("nonexistent", "SomePass123")
        self.assertEqual(status, "USER_NOT_FOUND")
        self.assertIsNone(role)

    def test_rbac_admin_full_permissions(self):
        self.assertTrue(self.has_permission("ADMIN", "wipe_drive"))
        self.assertTrue(self.has_permission("ADMIN", "manage_users"))

    def test_rbac_operator_restricted_permissions(self):
        self.assertTrue(self.has_permission("OPERATOR", "wipe_file"))
        self.assertFalse(self.has_permission("OPERATOR", "wipe_drive"))
        self.assertFalse(self.has_permission("OPERATOR", "manage_users"))

    def test_rbac_auditor_read_only_permission(self):
        self.assertTrue(self.has_permission("AUDITOR", "view_reports"))
        self.assertFalse(self.has_permission("AUDITOR", "wipe_file"))


if __name__ == "__main__":
    unittest.main()