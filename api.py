"""
api.py — Role 6: the functions everyone else calls.

INPUT functions (called by Roles 2-5):
    log_auth_event(event)
    log_device_event(event)
    log_sanitization_event(event)
    log_file_erase_event(event)
    log_verification_event(event)
    log_recovery_validation_event(event)

OUTPUT functions (called by Role 1 / GUI):
    get_assurance_score(operation_id)
    get_audit_log(limit, filter_event_type)
    verify_chain_integrity()
    generate_certificate(operation_id)
    generate_forensic_report(operation_id)
    export_audit_log_json(output_path)

Operation correlation (the fix for the missing operation_id in the
contract): an operation is opened the moment a sanitization or file-erase
event lands, keyed by target (device_path or file path). Later
verification / recovery-validation events for the SAME target get folded
into the most recent still-open operation for that target.
"""

import json
from datetime import datetime, timezone

try:
    from . import db
    from . import audit_chain
    from . import assurance
    from . import reports
except ImportError:
    import db
    import audit_chain
    import assurance
    import reports



class TrustLayer:
    def __init__(self, db_path: str = db.DB_PATH):
        # check_same_thread=False: Tkinter GUI callbacks and any background
        # threads (e.g. a device-watcher thread in Role 3) may call into
        # this from a different thread than the one that created it.
        # SQLite is fine with this as long as we don't write from two
        # threads at the EXACT same instant — for a single-USB hackathon
        # demo that's a non-issue.
        self.conn = db.get_connection(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL;")  # lets reads happen while a write is in progress
        db.init_schema(self.conn)

    # ---------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------

    def _new_operation_id(self) -> str:
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        cur = self.conn.execute(
            "SELECT COUNT(*) as c FROM operations WHERE operation_id LIKE ?", (f"OP-{today}-%",)
        )
        n = cur.fetchone()["c"] + 1
        return f"OP-{today}-{n:03d}"

    def _open_operation(self, op_type: str, target: str, performed_by: str, start_time: str) -> str:
        op_id = self._new_operation_id()
        self.conn.execute(
            """INSERT INTO operations (operation_id, op_type, target, status, performed_by, start_time)
               VALUES (?, ?, ?, 'OPEN', ?, ?)""",
            (op_id, op_type, target, performed_by, start_time),
        )
        self.conn.commit()
        return op_id

    def _find_open_operation_for_target(self, target: str):
        cur = self.conn.execute(
            "SELECT * FROM operations WHERE target = ? AND status = 'OPEN' ORDER BY start_time DESC LIMIT 1",
            (target,),
        )
        return cur.fetchone()

    def _update_operation_field(self, operation_id: str, field: str, payload: dict):
        self.conn.execute(
            f"UPDATE operations SET {field} = ? WHERE operation_id = ?",
            (json.dumps(payload), operation_id),
        )
        self.conn.commit()

    def _get_operation_dict(self, operation_id: str) -> dict:
        cur = self.conn.execute("SELECT * FROM operations WHERE operation_id = ?", (operation_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"No such operation: {operation_id}")
        op = dict(row)
        for jf in ("sanitization_json", "file_erase_json", "verification_json", "recovery_validation_json"):
            op[jf] = json.loads(op[jf]) if op[jf] else None
        return op

    # ---------------------------------------------------------------
    # INPUTS — Role 2
    # ---------------------------------------------------------------

    def log_auth_event(self, event: dict) -> dict:
        summary = f"{event.get('sub_type')} — {event.get('username', event.get('user_id',''))}"
        return audit_chain.append_entry(self.conn, event.get("event_type", "AUTH_EVENT"), event, summary)

    # ---------------------------------------------------------------
    # INPUTS — Role 3
    # ---------------------------------------------------------------

    def log_device_event(self, event: dict) -> dict:
        self.conn.execute(
            """INSERT INTO devices (device_path, serial, model, capacity_gb, filesystem, is_removable,
                                     first_detected_at, last_seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(device_path) DO UPDATE SET last_seen_at=excluded.last_seen_at""",
            (
                event["device_path"], event.get("serial"), event.get("model"), event.get("capacity_gb"),
                event.get("filesystem"), int(event.get("is_removable", False)),
                event.get("timestamp"), event.get("timestamp"),
            ),
        )
        self.conn.commit()
        summary = f"Device detected: {event.get('model')} ({event.get('device_path')})"
        return audit_chain.append_entry(self.conn, "DEVICE_DETECTED", event, summary)

    def log_sanitization_event(self, event: dict) -> dict:
        target = event["device_path"]
        op_id = event.get("operation_id")
        if not op_id:
            op_id = self._open_operation(
                "SANITIZATION", target, event.get("performed_by_user_id"), event.get("start_time")
            )
        else:
            cur = self.conn.execute("SELECT * FROM operations WHERE operation_id = ?", (op_id,))
            if not cur.fetchone():
                self.conn.execute(
                    """INSERT INTO operations (operation_id, op_type, target, status, performed_by, start_time)
                       VALUES (?, ?, ?, 'OPEN', ?, ?)""",
                    (op_id, "SANITIZATION", target, event.get("performed_by_user_id"), event.get("start_time")),
                )
                self.conn.commit()
        self._update_operation_field(op_id, "sanitization_json", event)
        self.conn.execute(
            "UPDATE operations SET end_time = ? WHERE operation_id = ?", (event.get("end_time"), op_id)
        )
        self.conn.commit()
        summary = f"{event.get('method')} wipe on {target} — {event.get('status')} [{op_id}]"
        entry = audit_chain.append_entry(self.conn, "SANITIZATION_COMPLETE", event, summary)
        entry["operation_id"] = op_id
        return entry

    # ---------------------------------------------------------------
    # INPUTS — Role 4
    # ---------------------------------------------------------------

    def log_file_erase_event(self, event: dict) -> dict:
        # target for correlation: first path if single, else a joined key for batch
        paths = event.get("target_paths", [])
        target = paths[0] if len(paths) == 1 else "|".join(paths)
        op_id = self._open_operation("FILE_ERASE", target, event.get("performed_by_user_id"), event.get("timestamp"))
        self._update_operation_field(op_id, "file_erase_json", event)
        self.conn.commit()
        summary = f"{event.get('operation')} erase — {event.get('files_succeeded')}/{event.get('files_total')} succeeded [{op_id}]"
        entry = audit_chain.append_entry(self.conn, "FILE_ERASE_COMPLETE", event, summary)
        entry["operation_id"] = op_id
        return entry

    def log_verification_event(self, event: dict) -> dict:
        target = event.get("target", "")
        op_row = None
        if event.get("operation_id"):
            cur = self.conn.execute("SELECT * FROM operations WHERE operation_id = ?", (event["operation_id"],))
            op_row = cur.fetchone()
        if not op_row and target:
            op_row = self._find_open_operation_for_target(target)
        if op_row:
            self._update_operation_field(op_row["operation_id"], "verification_json", event)
        summary = f"Verification {event.get('verdict')} on {target}"
        entry = audit_chain.append_entry(self.conn, "VERIFICATION_COMPLETE", event, summary)
        if op_row:
            entry["operation_id"] = op_row["operation_id"]
        return entry

    # ---------------------------------------------------------------
    # INPUTS — Role 5
    # ---------------------------------------------------------------

    def log_recovery_validation_event(self, event: dict) -> dict:
        target = event.get("device_path", "")
        op_row = None
        if event.get("operation_id"):
            cur = self.conn.execute("SELECT * FROM operations WHERE operation_id = ?", (event["operation_id"],))
            op_row = cur.fetchone()
        if not op_row and target:
            op_row = self._find_open_operation_for_target(target)
        if op_row:
            self._update_operation_field(op_row["operation_id"], "recovery_validation_json", event)
            self.conn.execute(
                "UPDATE operations SET status = 'CLOSED' WHERE operation_id = ?", (op_row["operation_id"],)
            )
            self.conn.commit()
        summary = f"Post-wipe recovery validation: {event.get('verdict')} on {target}"
        entry = audit_chain.append_entry(self.conn, "POST_WIPE_VALIDATION", event, summary)
        if op_row:
            entry["operation_id"] = op_row["operation_id"]
        return entry

    # ---------------------------------------------------------------
    # OUTPUTS — Role 1 / GUI
    # ---------------------------------------------------------------

    def get_assurance_score(self, operation_id: str) -> dict:
        op = self._get_operation_dict(operation_id)
        chain_status = audit_chain.verify_chain_integrity(self.conn)
        return assurance.compute_assurance_score(op, chain_status["chain_intact"])

    def get_audit_log(self, limit: int = 50, filter_event_type: str = None) -> list:
        return audit_chain.get_audit_log(self.conn, limit, filter_event_type)

    def verify_chain_integrity(self) -> dict:
        return audit_chain.verify_chain_integrity(self.conn)

    def generate_certificate(self, operation_id: str) -> str:
        op = self._get_operation_dict(operation_id)
        score = self.get_assurance_score(operation_id)
        path = reports.generate_certificate(op, score)
        self._record_certificate(operation_id, "CERTIFICATE", path)
        return path

    def generate_forensic_report(self, operation_id: str) -> str:
        op = self._get_operation_dict(operation_id)
        score = self.get_assurance_score(operation_id)
        audit_entries = self.get_audit_log(limit=200)
        path = reports.generate_forensic_report(op, score, audit_entries)
        self._record_certificate(operation_id, "FORENSIC_REPORT", path)
        return path

    def _record_certificate(self, operation_id: str, cert_type: str, path: str):
        cert_id = f"CERT-{operation_id}-{cert_type}"
        file_hash = reports.hash_file(path)
        self.conn.execute(
            """INSERT OR REPLACE INTO certificates (cert_id, operation_id, cert_type, file_path, generated_at, file_hash)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (cert_id, operation_id, cert_type, path, datetime.now(timezone.utc).isoformat(), file_hash),
        )
        self.conn.commit()

    def export_audit_log_json(self, output_path: str) -> bool:
        try:
            full_log = self.get_audit_log(limit=100000)
            with open(output_path, "w") as f:
                json.dump(full_log, f, indent=2)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------
# Singleton accessor — ALL roles should import and call this, not
# instantiate TrustLayer() themselves. One shared instance = one shared
# connection = everyone reading/writing the same persistent database,
# no risk of someone accidentally pointing at a different file path.
# ---------------------------------------------------------------------

_shared_instance = None


def get_trust_layer(db_path: str = db.DB_PATH) -> "TrustLayer":
    global _shared_instance
    if _shared_instance is None:
        _shared_instance = TrustLayer(db_path=db_path)
    return _shared_instance
