# SIH 26149 - Secure Data Erasure & Advanced File Recovery Tool

Prototype for NTRO's problem statement 26149 (Blockchain & Cybersecurity
theme): an integrated platform combining secure drive/file sanitization
with forensic recovery validation, audit logging, and reporting.

## Quick start

```bash
pip install -r requirements.txt   # tkinter itself ships with Python;
                                   # on Linux you may need: sudo apt install python3-tk
python3 main.py
```

## Demo logins

| Username | Password | Role | Sees |
|---|---|---|---|
| `admin` | `Admin@123456` | ADMIN | Everything |
| `operator1` | `Operator@123` | OPERATOR | Device (Sanitize + quick Post-Wipe Validation), File Eraser, Verification |
| `investigator1` | `Investigator@123` | INVESTIGATOR | Device (view-only), Recovery/Carving, Assurance & Audit, Reports/Certificates |

Each role only sees the tabs it's permitted - not just grayed out, but
actually hidden - and the backend enforces the same permission checks
independently, so the restriction holds even if a call bypasses the GUI.

## Team split (6 roles)

| # | Owns | Status |
|---|------|--------|
| 1 | GUI/Dashboard (this repo's `gui/`) | Done |
| 2 | Auth & RBAC | Stub in `backend/auth/` - matches signed-off `Role2.docx`, one addition (`VALIDATE_SANITIZATION`) flagged for confirmation |
| 3 | Device Detection & Sanitization Engine | Stub in `backend/role3_sanitization.py` - interface not yet confirmed |
| 4 | File/Folder Eraser & Verification | Stub in `backend/role4_file_ops.py` - interface not yet confirmed |
| 5 | Forensics / Recovery | Stub in `backend/person5_final/` - matches signed-off spec |
| 6 | Trust Layer (audit/assurance/certificates) | Stub in `backend/role6_trust.py` - matches signed-off spec |

See **INTEGRATION.md** for exactly how each teammate plugs their real
module into this GUI.
