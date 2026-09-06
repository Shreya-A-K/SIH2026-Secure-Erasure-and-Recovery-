"""
confidence_score.py
Person 5 — Forensics/Recovery module

Recovery Confidence Score:
A 0-100 explainable score expressing confidence that a recovered
artifact is correctly identified, structurally valid, readable,
and not obviously corrupted.

IMPORTANT:
The score is NOT the percentage of the original file recovered.

Evidence used:
    - Signature validity
    - File structure validation
    - Open/parse validation
    - Completeness/size evidence
    - Corruption indicators
"""

import os
from dataclasses import dataclass
from typing import Dict

from recovery_engine import RecoveredFile


# --------------------------------------------------------------------------
# File signatures
# --------------------------------------------------------------------------

MAGIC_BYTES = {
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "pdf": [b"%PDF-"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "zip": [b"PK\x03\x04"],
    "gif": [b"GIF87a", b"GIF89a"],
}


# --------------------------------------------------------------------------
# Signature validation
# --------------------------------------------------------------------------

def check_signature(rf: RecoveredFile) -> bool:
    """
    Check whether the recovered file begins with the expected
    magic bytes for its detected file type.
    """

    file_type = (rf.file_type or "").lower().lstrip(".")

    magics = MAGIC_BYTES.get(file_type)

    # Unknown type: cannot perform a signature check.
    if not magics:
        return False

    try:
        with open(rf.out_path, "rb") as f:
            head = f.read(32)

        return any(head.startswith(magic) for magic in magics)

    except OSError:
        return False


# --------------------------------------------------------------------------
# Structural validation
# --------------------------------------------------------------------------

def validate_structure(rf: RecoveredFile) -> bool:
    """
    Perform lightweight format-specific structural validation.

    Currently implemented:
        PNG -> verify PNG end marker (IEND)

    Other formats fall back to signature validation.
    """

    file_type = (rf.file_type or "").lower().lstrip(".")

    try:
        with open(rf.out_path, "rb") as f:
            data = f.read()

        if not data:
            return False

        if file_type == "png":
            # PNG must contain the IEND chunk.
            return b"IEND" in data

        if file_type in ("jpg", "jpeg"):
            # JPEG normally ends with FF D9.
            return data.endswith(b"\xff\xd9")

        if file_type == "pdf":
            # PDF should contain EOF marker.
            return b"%%EOF" in data

        # For formats without a simple structural check,
        # successful signature validation is our basic evidence.
        return check_signature(rf)

    except OSError:
        return False


# --------------------------------------------------------------------------
# Open / parser validation
# --------------------------------------------------------------------------

def validate_openable(rf: RecoveredFile) -> bool:
    """
    Try to parse the recovered file using an appropriate parser.

    Pillow is used for image formats.
    PDFs use a lightweight EOF/structure check.
    Other formats fall back to structural validation.
    """

    file_type = (rf.file_type or "").lower().lstrip(".")

    try:

        if file_type in ("png", "jpg", "jpeg", "gif"):
            from PIL import Image

            with Image.open(rf.out_path) as image:
                image.verify()

            return True

        if file_type == "pdf":
            with open(rf.out_path, "rb") as f:
                data = f.read()

            return data.startswith(b"%PDF-") and b"%%EOF" in data

        return validate_structure(rf)

    except Exception:
        return False


# --------------------------------------------------------------------------
# Completeness / size evidence
# --------------------------------------------------------------------------

def completeness_score(rf: RecoveredFile) -> int:
    """
    Estimate how much evidence we have about completeness.

    If filesystem metadata provides an expected size, compare the
    recovered size against it.

    For signature-based carving there is no original size available,
    so only partial credit is awarded.
    """

    if rf.expected_size and rf.expected_size > 0:

        ratio = rf.recovered_size / rf.expected_size

        if ratio >= 1.0:
            return 15

        if ratio >= 0.95:
            return 14

        if ratio >= 0.75:
            return 10

        if ratio >= 0.50:
            return 7

        return 3

    # Carving has no filesystem ground truth.
    # Therefore we deliberately do not claim completeness.
    return 8


# --------------------------------------------------------------------------
# Corruption check
# --------------------------------------------------------------------------

def corruption_check(rf: RecoveredFile) -> bool:
    """
    Return True when there are no obvious corruption indicators.

    This is deliberately conservative:
    successful parser verification counts as strong evidence.
    """

    if rf.recovered_size <= 0:
        return False

    if not check_signature(rf):
        return False

    if not validate_structure(rf):
        return False

    if not validate_openable(rf):
        return False

    return True


# --------------------------------------------------------------------------
# Main confidence calculation
# --------------------------------------------------------------------------

def compute_confidence(rf: RecoveredFile) -> Dict:
    """
    Return a complete explainable confidence result.

    Score components:

        Signature       25
        Structure       25
        Open/Parse      20
        Completeness    15
        No corruption   15

        Maximum = 100
    """

    breakdown = {}

    # 1. Signature
    signature_ok = check_signature(rf)
    breakdown["signature"] = 25 if signature_ok else 0

    # 2. Structure
    structure_ok = validate_structure(rf)
    breakdown["structure"] = 25 if structure_ok else 0

    # 3. Open / parser validation
    openable_ok = validate_openable(rf)
    breakdown["open_parse"] = 20 if openable_ok else 0

    # 4. Completeness / size evidence
    breakdown["completeness"] = completeness_score(rf)

    # 5. Corruption check
    corruption_ok = corruption_check(rf)
    breakdown["corruption_check"] = 15 if corruption_ok else 0

    score = sum(breakdown.values())
    score = max(0, min(100, score))

    return {
        "score": score,
        "breakdown": breakdown,
        "signature_valid": signature_ok,
        "structure_valid": structure_ok,
        "open_parse_valid": openable_ok,
        "corruption_check_passed": corruption_ok,
        "label": _label(score),
    }


# --------------------------------------------------------------------------
# Score classification
# --------------------------------------------------------------------------

def _label(score: int) -> str:

    if score >= 80:
        return "HIGH"

    if score >= 60:
        return "MEDIUM-HIGH"

    if score >= 40:
        return "MEDIUM"

    if score >= 20:
        return "LOW"

    return "VERY LOW"


# --------------------------------------------------------------------------
# Batch scoring
# --------------------------------------------------------------------------

def score_batch(files):
    """
    Score all recovered files.

    Output is a list of dictionaries containing:
        - original RecoveredFile information
        - confidence score
        - score breakdown
        - validation results

    This output can be consumed by Person 1's GUI and
    Person 6's reporting/audit layer.
    """

    out = []

    for rf in files:

        result = compute_confidence(rf)

        out.append({
            **rf.as_dict(),
            **result
        })

    return out
