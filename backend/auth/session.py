"""
Person 2 - Authentication + RBAC : session.py
===============================================
STUB matching Role2.docx section 4 exactly. Person 2: replace the
in-memory _session dict with your real session backend (e.g. a
server-side session store keyed by token), keep these three function
names and signatures.
"""

_session = {"user": None}


def login_user(user: dict):
    """Called by Person 1 right after a successful authenticate()."""
    _session["user"] = user


def logout():
    """Called by Person 1 when the user clicks Logout."""
    _session["user"] = None


def get_current_user():
    """Called by any module that needs to know who is logged in."""
    return _session["user"]
