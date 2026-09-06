"""
Person 2 - Authentication + RBAC : login.py
=============================================
STUB matching Role2.docx section 2/3 exactly (authenticate() returns
user details or None). Person 2: replace _USERS with your real SQLite
`users` table lookup (with real password hashing - this stub uses
plaintext for demo purposes only), keep the function name/signature
and the returned dict shape: {"id", "username", "role"}.
"""

from datetime import datetime, timezone

from backend import role6_trust

# STUB user table - Person 2's real version reads this from SQLite.
# Passwords here are plaintext for demo convenience only - never do
# this in the real implementation, use a proper hash (e.g. bcrypt).
_USERS = {
    "admin":         {"id": 1, "username": "admin",         "password": "Admin@123456",       "role": "ADMIN",        "enabled": True},
    "operator1":     {"id": 2, "username": "operator1",     "password": "Operator@123",        "role": "OPERATOR",     "enabled": True},
    "investigator1": {"id": 3, "username": "investigator1", "password": "Investigator@123",    "role": "INVESTIGATOR", "enabled": True},
}


def authenticate(username: str, password: str):
    """
    Returns a user dict {"id", "username", "role"} on success, or None
    on failure (wrong password, unknown user, or disabled account).
    """
    record = _USERS.get(username)
    success = bool(record and record.get("enabled") and record["password"] == password)

    event = {
        "event_type": "AUTH_EVENT",
        "sub_type": "LOGIN_SUCCESS" if success else "LOGIN_FAIL",
        "user_id": record["id"] if (record and success) else None,
        "username": username,
        "role": record["role"] if (record and success) else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "notes": "" if success else ("Account disabled" if record and not record.get("enabled")
                                      else "Invalid credentials"),
    }
    role6_trust.log_auth_event(event)

    if success:
        return {"id": record["id"], "username": record["username"], "role": record["role"]}
    return None
