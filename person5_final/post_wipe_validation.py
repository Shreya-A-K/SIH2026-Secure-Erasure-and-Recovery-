"""
post_wipe_validation.py
Person 5 — Forensics/Recovery module

After Person 3's Sanitization Engine wipes a device, this module runs a
RESTRICTED recovery attempt against it and produces a PASS/FAIL verdict
that feeds Person 6's Assurance Score engine and the certificate.

"Restricted" = deliberately narrower than a full forensic investigation:
  - quick scope by default (metadata/inode-table scan + a bounded carving pass,
    not a full-disk deep carve) to keep the demo fast
  - result is a verdict + evidence list, not a full recovery workspace
  - meant to answer one question: "did the wipe actually remove recoverable
    data, or does something come back?"

This is the RBAC boundary point in the architecture: this function should
only ever be callable in "Sanitization Verification" mode, never exposed as
a general investigator recovery run on arbitrary evidence — that's a
separate code path Person 2's RBAC layer should gate.
"""

import os
import tempfile
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional

from recovery_engine import run_full_recovery, RecoveredFile
from confidence_score import compute_confidence

# Below this confidence score, a "recovered" artifact is treated as noise
# (partial slack-space fragments, filesystem journal remnants) rather than
# a real failure of the wipe.
FAIL_CONFIDENCE_THRESHOLD = 40


@dataclass
class ValidationResult:
    device_path: str
    verdict: str                      # "PASS" | "FAIL"
    scope: str                        # "quick" | "full"
    artifacts_found: int
    qualifying_artifacts: int         # artifacts above FAIL_CONFIDENCE_THRESHOLD
    evidence: List[Dict] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    notes: str = ""

    def __getitem__(self, item):
        if item == "validation_status":
            return self.verdict
        return getattr(self, item)

    def get(self, item, default=None):
        if item == "validation_status":
            return self.verdict
        return getattr(self, item, default)

    def as_dict(self):
        return {
            "device_path": self.device_path,
            "verdict": self.verdict,
            "validation_status": self.verdict,
            "scope": self.scope,
            "artifacts_found": self.artifacts_found,
            "qualifying_artifacts": self.qualifying_artifacts,
            "evidence": self.evidence,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "notes": self.notes,
        }


def run_post_wipe_scan(device_path, scope: str = "quick",
                        work_dir: Optional[str] = None,
                        cleanup: bool = True) -> ValidationResult:
    """
    scope="quick": pytsk3 inode/MFT scan only (fast, catches the common case
                   where a wipe left filesystem metadata structures intact).
    scope="full":  quick scan + Scalpel + Foremost carving pass (slower,
                   use for the final certificate-grade validation).
    """
    if isinstance(device_path, dict):
        req = device_path
        device_path = req.get("device_path", "./test.img")
        scope = req.get("scope", scope)

    started = datetime.now(timezone.utc).isoformat()
    own_tmp = work_dir is None
    work_dir = work_dir or tempfile.mkdtemp(prefix="postwipe_")

    try:
        if scope == "quick":
            recovered = run_full_recovery(
                device_path, work_dir,
                use_tsk=True, use_scalpel=False, use_foremost=False,
            )
        elif scope == "full":
            recovered = run_full_recovery(
                device_path, work_dir,
                use_tsk=True, use_scalpel=True, use_foremost=True,
            )
        else:
            raise ValueError("scope must be 'quick' or 'full'")

        scored = []
        for rf in recovered:
            result = compute_confidence(rf)
            scored.append({**rf.as_dict(), **result})

        qualifying = [s for s in scored if s["score"] >= FAIL_CONFIDENCE_THRESHOLD]

        if len(qualifying) == 0:
            verdict = "PASS"
            notes = f"No artifacts scored >= {FAIL_CONFIDENCE_THRESHOLD} confidence."
        else:
            verdict = "FAIL"
            notes = f"{len(qualifying)} qualifying artifact(s) recovered above confidence threshold."

        result = ValidationResult(device_path=device_path,verdict=verdict, scope=scope,artifacts_found=len(scored),qualifying_artifacts=len(qualifying),evidence=scored, started_at=started,finished_at=datetime.now(timezone.utc).isoformat(), notes=notes,)
        return result
    finally:
        if cleanup and own_tmp and os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)


def to_audit_event(result) -> Dict:
    """
    Shape expected by Person 6's hash-chain audit logger. Hand this dict
    straight to their `audit_logger.append_event(...)` — do not log the
    full recovered file bytes/paths, only summary + hashes, to keep the
    audit chain lightweight and avoid re-exposing recovered content.
    """
    if isinstance(result, dict):
        evidence = result.get("evidence", [])
        return {
            "event_type": "POST_WIPE_VALIDATION",
            "device_path": result.get("device_path", ""),
            "verdict": result.get("verdict") or result.get("validation_status", "PASS"),
            "scope": result.get("scope", "quick"),
            "artifacts_found": result.get("artifacts_found", 0),
            "qualifying_artifacts": result.get("qualifying_artifacts", 0),
            "evidence_hashes": [e["sha256"] for e in evidence if e.get("sha256")],
            "timestamp": result.get("finished_at", datetime.now(timezone.utc).isoformat()),
            "notes": result.get("notes", ""),
        }
    return {
        "event_type": "POST_WIPE_VALIDATION",
        "device_path": result.device_path,
        "verdict": result.verdict,
        "scope": result.scope,
        "artifacts_found": result.artifacts_found,
        "qualifying_artifacts": result.qualifying_artifacts,
        "evidence_hashes": [e["sha256"] for e in result.evidence if e.get("sha256")],
        "timestamp": result.finished_at,
        "notes": result.notes,
    }
