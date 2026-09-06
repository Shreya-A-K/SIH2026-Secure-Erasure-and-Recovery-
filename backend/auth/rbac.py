"""
Person 2 - Authentication + RBAC : rbac.py
=============================================
STUB matching Role2.docx section 5 exactly (the "EXACT PERMISSION
CONTRACT" table). has_permission() checks the CURRENT SESSION - it
takes only a permission name, never a role - matching every example
in section 6 of the doc: `if has_permission("SANITIZE_USB"): ...`

Person 2: replace with your real role/permission lookup (e.g. from a
`roles` / `permissions` SQLite table), keep the function name and
single-argument signature.
"""

from .session import get_current_user

# Exact table from Role2.docx section 5.
PERMISSIONS = {
    "DETECT_USB":       {"ADMIN", "OPERATOR", "INVESTIGATOR"},
    "SANITIZE_USB":     {"ADMIN", "OPERATOR"},
    "ERASE_FILE":       {"ADMIN", "OPERATOR"},
    "RECOVER_FILES":    {"ADMIN", "INVESTIGATOR"},
    "VIEW_RECOVERY":    {"ADMIN", "INVESTIGATOR"},
    "GENERATE_REPORT":  {"ADMIN", "INVESTIGATOR"},
    "VIEW_AUDIT":       {"ADMIN", "INVESTIGATOR"},
    "MANAGE_USERS":     {"ADMIN"},

    # --- Person 1 addition, NOT in the original Role2.docx table ---
    # Needed so an OPERATOR can run a quick post-wipe check right on
    # the Device page after their own sanitize job, without needing
    # full RECOVER_FILES/VIEW_RECOVERY access to the Recovery page.
    # Flag this with Person 2 and Person 5 before final integration -
    # confirm the permission name and allowed roles.
    "VALIDATE_SANITIZATION": {"ADMIN", "OPERATOR"},
}


def has_permission(permission: str) -> bool:
    user = get_current_user()
    if not user:
        return False
    return user.get("role") in PERMISSIONS.get(permission, set())
