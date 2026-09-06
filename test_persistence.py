"""
test_persistence.py — Proves data survives across separate process runs,
using the SAME persistent trust_layer.db that your teammates will use.

Run this TWICE:
    python3 -m role6_trust_layer.test_persistence

First run: writes one login event, tells you the row count.
Second run: shows the row count went UP by one (old data is still there).

This is different from demo.py, which deletes and rebuilds a throwaway
DB every time — this script never deletes anything.
"""

from datetime import datetime, timezone
try:
    from .api import get_trust_layer
except ImportError:
    from api import get_trust_layer



def run():
    tl = get_trust_layer()  # uses the real persistent trust_layer.db

    before = tl.conn.execute("SELECT COUNT(*) as c FROM audit_log").fetchone()["c"]
    print(f"Audit log entries BEFORE this run: {before}")

    tl.log_auth_event({
        "event_type": "AUTH_EVENT", "sub_type": "LOGIN_SUCCESS",
        "user_id": "operator_01", "username": "john_doe", "role": "OPERATOR",
        "timestamp": datetime.now(timezone.utc).isoformat(), "notes": "persistence test",
    })

    after = tl.conn.execute("SELECT COUNT(*) as c FROM audit_log").fetchone()["c"]
    print(f"Audit log entries AFTER this run:  {after}")
    print("If you run this script again, BEFORE should equal this run's AFTER.")
    print("That confirms the database is truly persistent across runs.")


if __name__ == "__main__":
    run()
