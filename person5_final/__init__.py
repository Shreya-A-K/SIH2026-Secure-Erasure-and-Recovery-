"""
Forensics and recovery module (Person 5).
"""

import os
import sys

# Ensure local module directory is in sys.path so intra-package imports resolve cleanly
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

from .recovery_engine import (
    RecoveredFile,
    RecoveryError,
    TSKRecovery,
    CarvingRecovery,
    run_full_recovery,
)
from .confidence_score import (
    MAGIC_BYTES,
    check_signature,
    validate_structure,
    validate_openable,
    completeness_score,
    corruption_check,
    compute_confidence,
    score_batch,
)
from .post_wipe_validation import (
    ValidationResult,
    run_post_wipe_scan,
    to_audit_event,
)

__all__ = [
    "RecoveredFile",
    "RecoveryError",
    "TSKRecovery",
    "CarvingRecovery",
    "run_full_recovery",
    "MAGIC_BYTES",
    "check_signature",
    "validate_structure",
    "validate_openable",
    "completeness_score",
    "corruption_check",
    "compute_confidence",
    "score_batch",
    "ValidationResult",
    "run_post_wipe_scan",
    "to_audit_event",
]
