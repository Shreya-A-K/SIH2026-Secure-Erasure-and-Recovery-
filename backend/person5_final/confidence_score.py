"""
Person 5 - Forensics / Recovery
Confidence scoring for recovered files. STUB - see recovery_engine.py.
"""


def _label_for(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 25:
        return "LOW"
    return "VERY LOW"


def score_batch(files: list) -> list:
    """
    Takes a list of raw recovered-file dicts and returns the same list
    with confidence_score (0-100) and confidence_label added.
    Person 5: replace the scoring heuristic with your real signature-
    based / carving-quality logic.
    """
    scored = []
    for f in files:
        score = f.get("confidence_score", 15)  # STUB default
        scored.append({**f, "confidence_score": score, "confidence_label": _label_for(score)})
    return scored
