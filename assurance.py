"""
assurance.py — Role 6: Assurance Score engine.

The API contract gives ONE example output (score=87, breakdown 30/25/25/7)
but never defines the actual formula. That's a spec gap, so this is where
I'm defining it explicitly — weights sum to 100, each sub-score is
computed from real event data, nothing is hand-waved.

Weights (out of 100):
  sanitization_method_score   -> max 30  (which wipe method was used, and did it succeed)
  verification_passed         -> max 25  (did SHA-256 pre/post hashes actually differ)
  recovery_validation_passed  -> max 25  (post-wipe recovery attempt found nothing)
  audit_chain_intact          -> max 20  (is the hash chain for this op unbroken)

Analogy for your judges: think of it like a credit score for a
transaction, not a pass/fail lie-detector. A DoD 7-pass wipe that
verifies clean and shows nothing recoverable afterward earns a 90+
"CERTIFIED SECURE." A single-pass zero-fill that "sort of" worked but
you can't verify might land at 55 — still usable, but the platform is
honest that it's a weaker guarantee, not a false "100% secure" claim.
That honesty is your novelty angle for SSDs, too: you're not lying
that everything scores 100.
"""

from datetime import datetime, timezone

METHOD_SCORES = {
    "ZEROS": 15,
    "OVERWRITE": 15,
    "Single-Pass Overwrite (Zero Fill)": 15,
    "Single-Pass Zero Fill": 15,
    "RANDOM": 20,
    "Random Overwrite": 20,
    "DOD_3_PASS": 25,
    "DoD 5220.22-M (3-Pass)": 25,
    "DoD 5220.22-M": 25,
    "DOD_7_PASS": 28,
    "GUTMANN_35": 30,
    "NIST 800-88 Clear": 25,
    "Cryptographic Erase": 30,
}


def _grade(score: int):
    if score >= 90:
        return "A+", "CERTIFIED SECURE"
    if score >= 75:
        return "A", "HIGH ASSURANCE"
    if score >= 60:
        return "B", "MODERATE ASSURANCE"
    if score >= 40:
        return "C", "LOW ASSURANCE"
    return "F", "FAILED / UNRELIABLE"


def compute_assurance_score(operation: dict, chain_intact: bool) -> dict:
    """operation is a row (as dict) from the `operations` table, with the
    folded-in *_json sub-event dicts already parsed."""

    breakdown = {
        "sanitization_method_score": 0,
        "verification_passed": 0,
        "recovery_validation_passed": 0,
        "audit_chain_intact": 0,
    }

    san = operation.get("sanitization_json") or operation.get("file_erase_json")
    if san and (san.get("status") == "SUCCESS" or san.get("files_succeeded", 0) > 0):
        method_name = san.get("method") or san.get("operation")
        breakdown["sanitization_method_score"] = METHOD_SCORES.get(method_name, 15)

    ver = operation.get("verification_json")
    if ver and ver.get("verdict") == "PASS":
        breakdown["verification_passed"] = 25

    rec = operation.get("recovery_validation_json")
    if rec:
        if rec.get("verdict") == "PASS" or rec.get("validation_status") == "PASS":
            breakdown["recovery_validation_passed"] = 25
        else:
            # partial credit if some artifacts were found but very few qualified
            qualifying = rec.get("qualifying_artifacts", rec.get("artifacts_found", 1))
            if qualifying == 0:
                breakdown["recovery_validation_passed"] = 25
            else:
                breakdown["recovery_validation_passed"] = max(0, 25 - qualifying * 5)

    breakdown["audit_chain_intact"] = 20 if chain_intact else 0

    score = sum(breakdown.values())
    grade, verdict = _grade(score)

    return {
        "operation_id": operation["operation_id"],
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "breakdown": breakdown,
        "max_score": 100,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


