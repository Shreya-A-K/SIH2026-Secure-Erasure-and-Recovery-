"""
db.py — Role 6: SQLite schema owner.

Tables owned here (per API contract):
  users, devices, operations, audit_log, certificates

No other role is allowed to write to audit_log or certificates directly —
they only ever call functions in api.py, which call into here.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "trust_layer.db")


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id     TEXT PRIMARY KEY,
            username    TEXT NOT NULL,
            role        TEXT NOT NULL CHECK(role IN ('OPERATOR','INVESTIGATOR','ADMIN')),
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_path       TEXT PRIMARY KEY,
            serial            TEXT,
            model             TEXT,
            capacity_gb       REAL,
            filesystem        TEXT,
            is_removable      INTEGER,
            first_detected_at TEXT,
            last_seen_at      TEXT
        );

        CREATE TABLE IF NOT EXISTS operations (
            operation_id   TEXT PRIMARY KEY,
            op_type        TEXT NOT NULL,   -- SANITIZATION | FILE_ERASE
            target         TEXT NOT NULL,   -- device_path or file/folder path
            status         TEXT NOT NULL DEFAULT 'OPEN', -- OPEN | CLOSED
            performed_by   TEXT,
            start_time     TEXT,
            end_time       TEXT,
            -- raw sub-event data folded in as JSON, so assurance.py can score without re-joining tables
            sanitization_json TEXT,
            file_erase_json   TEXT,
            verification_json TEXT,
            recovery_validation_json TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            sequence    INTEGER NOT NULL,
            event_type  TEXT NOT NULL,
            summary     TEXT,
            payload_json TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            prev_hash   TEXT NOT NULL,
            hash        TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS certificates (
            cert_id       TEXT PRIMARY KEY,
            operation_id  TEXT,
            cert_type     TEXT NOT NULL,  -- CERTIFICATE | FORENSIC_REPORT
            file_path     TEXT NOT NULL,
            generated_at  TEXT NOT NULL,
            file_hash     TEXT,
            FOREIGN KEY(operation_id) REFERENCES operations(operation_id)
        );
        """
    )
    conn.commit()
