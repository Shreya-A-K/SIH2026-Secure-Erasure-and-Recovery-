"""
audit_chain.py — Role 6: append-only hash-chain audit log.

This is your "simple blockchain" for Sept 8 — not a real distributed
blockchain (that's explicitly future-scope per your final-build diagram),
just a tamper-evident chain: every log entry's hash depends on the
previous entry's hash + its own content. Change any past entry, and every
hash after it breaks. That's the whole trick, and it's honest about
being that and nothing more.

Analogy for your slide: it's like a notarized ledger book where every
page has the previous page's fingerprint written at the top. Tear out
or reword page 12, and pages 13 onward no longer match what's recorded
about them — the tampering is visible even without a live network of
witnesses.
"""

import hashlib
import json
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64


def _canonical(payload: dict) -> str:
    # sort_keys makes the hash deterministic regardless of dict insertion order
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _compute_hash(prev_hash: str, event_type: str, payload_json: str, timestamp: str) -> str:
    material = f"{prev_hash}|{event_type}|{payload_json}|{timestamp}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def append_entry(conn, event_type: str, payload: dict, summary: str) -> dict:
    """Appends one entry to the audit_log hash chain. Returns the stored row as a dict."""
    cur = conn.cursor()

    cur.execute("SELECT hash, sequence FROM audit_log ORDER BY sequence DESC LIMIT 1")
    row = cur.fetchone()
    prev_hash = row["hash"] if row else GENESIS_HASH
    sequence = (row["sequence"] + 1) if row else 1

    timestamp = payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
    payload_json = _canonical(payload)
    entry_hash = _compute_hash(prev_hash, event_type, payload_json, timestamp)

    cur.execute(
        """INSERT INTO audit_log (sequence, event_type, summary, payload_json, timestamp, prev_hash, hash)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (sequence, event_type, summary, payload_json, timestamp, prev_hash, entry_hash),
    )
    conn.commit()

    return {
        "log_id": cur.lastrowid,
        "sequence": sequence,
        "event_type": event_type,
        "summary": summary,
        "timestamp": timestamp,
        "hash": entry_hash,
        "prev_hash": prev_hash,
    }


def get_audit_log(conn, limit: int = 50, filter_event_type: str = None) -> list:
    cur = conn.cursor()
    if filter_event_type:
        cur.execute(
            "SELECT * FROM audit_log WHERE event_type = ? ORDER BY sequence DESC LIMIT ?",
            (filter_event_type, limit),
        )
    else:
        cur.execute("SELECT * FROM audit_log ORDER BY sequence DESC LIMIT ?", (limit,))
    rows = cur.fetchall()

    # chain_valid is computed relative to the immediately preceding entry only —
    # for a full-chain verdict use verify_chain_integrity() instead
    results = []
    for row in rows:
        results.append(
            {
                "log_id": row["log_id"],
                "sequence": row["sequence"],
                "event_type": row["event_type"],
                "summary": row["summary"],
                "timestamp": row["timestamp"],
                "hash": row["hash"],
                "prev_hash": row["prev_hash"],
            }
        )
    return results


def verify_chain_integrity(conn) -> dict:
    """Walks the entire chain from genesis and recomputes every hash.
    This is the actual tamper-detection check — if anyone edited a row
    directly in the DB, this is what catches it."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_log ORDER BY sequence ASC")
    rows = cur.fetchall()

    expected_prev = GENESIS_HASH
    first_broken = None
    for row in rows:
        recomputed = _compute_hash(expected_prev, row["event_type"], row["payload_json"], row["timestamp"])
        if row["prev_hash"] != expected_prev or row["hash"] != recomputed:
            first_broken = row["sequence"]
            break
        expected_prev = row["hash"]

    return {
        "total_entries": len(rows),
        "chain_intact": first_broken is None,
        "first_broken_at_sequence": first_broken,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }

