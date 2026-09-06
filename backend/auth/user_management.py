"""
Person 2 - Authentication + RBAC : user_management.py
========================================================
STUB matching Role2.docx section 2/3 (create_user, disable_user,
enable_user, change_role, change_password, get_all_users). All of
these are ADMIN-only (MANAGE_USERS permission).

NOTE: no GUI screen calls these yet - Person 1 has not built an Admin
"Manage Users" page. These are here so the contract is complete and
Person 2's real module has something to drop into. Ask Person 1 if
you want a Users tab added to the dashboard.
"""

from .rbac import has_permission
from .login import _USERS  # STUB only - Person 2's real version uses SQLite, not this dict

VALID_ROLES = {"ADMIN", "OPERATOR", "INVESTIGATOR"}


def create_user(username: str, password: str, role: str):
    if not has_permission("MANAGE_USERS"):
        return False, "Access denied: MANAGE_USERS permission required."
    if username in _USERS:
        return False, f"User '{username}' already exists."
    if role not in VALID_ROLES:
        return False, f"Invalid role '{role}'."
    new_id = max((u["id"] for u in _USERS.values()), default=0) + 1
    _USERS[username] = {"id": new_id, "username": username, "password": password, "role": role, "enabled": True}
    return True, f"User '{username}' created with role {role}."


def disable_user(username: str):
    if not has_permission("MANAGE_USERS"):
        return False, "Access denied: MANAGE_USERS permission required."
    if username not in _USERS:
        return False, f"User '{username}' not found."
    _USERS[username]["enabled"] = False
    return True, f"User '{username}' disabled."


def enable_user(username: str):
    if not has_permission("MANAGE_USERS"):
        return False, "Access denied: MANAGE_USERS permission required."
    if username not in _USERS:
        return False, f"User '{username}' not found."
    _USERS[username]["enabled"] = True
    return True, f"User '{username}' enabled."


def change_role(username: str, new_role: str):
    if not has_permission("MANAGE_USERS"):
        return False, "Access denied: MANAGE_USERS permission required."
    if username not in _USERS:
        return False, f"User '{username}' not found."
    if new_role not in VALID_ROLES:
        return False, f"Invalid role '{new_role}'."
    _USERS[username]["role"] = new_role
    return True, f"'{username}' role changed to {new_role}."


def change_password(username: str, old_password: str, new_password: str):
    record = _USERS.get(username)
    if not record or record["password"] != old_password:
        return False, "Current password is incorrect."
    record["password"] = new_password
    return True, "Password changed."


def get_all_users():
    if not has_permission("MANAGE_USERS"):
        return []
    return [{"id": u["id"], "username": u["username"], "role": u["role"], "enabled": u["enabled"]}
            for u in _USERS.values()]
