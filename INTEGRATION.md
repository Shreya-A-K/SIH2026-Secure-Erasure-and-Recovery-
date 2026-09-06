# SIH 26149 - Integration Guide
### Secure Data Erasure & Advanced File Recovery Tool (NTRO)

This document is for **all six team members**. It explains the folder
structure, exactly what each of you needs to hand over, and how your
module plugs into the GUI Person 1 (Roshini) has already built and
tested.

## 1. How the whole app fits together

```
GUI (Person 1)
   |
   v
Role 2 (Auth/RBAC) --checks--> Role 3 (Sanitization) --or--> Role 4 (File Ops)
                                        |                        |
                                        v                        v
                                  Role 5 (Forensics/Recovery validation)
                                        |
                                        v
                                  Role 6 (Trust Layer: audit, score, PDFs)
                                        |
                                        v
                                   back to GUI
```

The GUI is done and **already runs end-to-end today** using stub
("fake but correctly-shaped") backend modules, with real RBAC enforced
throughout - both in the GUI (restricted tabs are hidden, not just
grayed out) and in the backend (every protected function checks
`has_permission()` before doing real work, per Role2.docx section 7).
This means:
- You can demo the full app right now, before anyone's real module is ready.
- When your module is ready, you replace ONE file (or one folder, for
  Persons 2 and 5) with your real code - the GUI does not change.

## 2. Folder structure

```
sih_project/
├── main.py                      <- run this to launch the app
├── requirements.txt
├── gui/                         <- Person 1 owns this folder entirely
│   ├── app.py                   <- App controller (page switching, session display)
│   ├── theme.py                 <- colors/fonts/ttk styles for the whole app
│   ├── login_page.py            <- calls backend/auth/login.py + session.py
│   ├── dashboard_page.py        <- sidebar nav, gated on backend/auth/rbac.py
│   └── pages/
│       ├── device_page.py       <- calls backend/role3_sanitization.py + auth/rbac.py
│       ├── file_eraser_page.py  <- calls backend/role4_file_ops.py
│       ├── verification_page.py <- calls backend/role4_file_ops.py
│       ├── recovery_page.py     <- calls backend/person5_final/ + auth/rbac.py
│       ├── assurance_page.py    <- calls backend/role6_trust.py
│       └── reports_page.py      <- calls backend/role6_trust.py
└── backend/                     <- each teammate replaces their own file(s)
    ├── auth/                    <- PERSON 2 replaces this whole folder
    │   ├── login.py             <- authenticate(username, password)
    │   ├── session.py           <- login_user(user), logout(), get_current_user()
    │   ├── rbac.py              <- has_permission(permission_name)
    │   └── user_management.py   <- create_user/disable_user/enable_user/change_role/
    │                                change_password/get_all_users (ADMIN only, no
    │                                GUI screen built for these yet)
    ├── role3_sanitization.py    <- PERSON 3 replaces this
    ├── role4_file_ops.py        <- PERSON 4 replaces this
    ├── person5_final/           <- PERSON 5 replaces this whole folder
    │   ├── recovery_engine.py
    │   ├── confidence_score.py
    │   └── post_wipe_validation.py
    └── role6_trust.py           <- PERSON 6 replaces this
```

## 3. What each person needs to do

**Rule for everyone:** keep the exact function names, argument order,
and returned dict keys that are already in your stub file. The GUI
calls those names directly. If you must change a signature, message
Person 1 first so the GUI call site gets updated too.

### Person 2 - Auth & RBAC
Folder: `backend/auth/`
- **Fully specified in `Role2.docx`** - the stub already matches it
  exactly: `authenticate(username, password)` returns a user dict or
  `None`; `login_user(user)` / `logout()` / `get_current_user()` manage
  the session; `has_permission(permission_name)` checks the *current
  session* (not a role you pass in) against the permission table.
- Replace `_USERS` in `login.py` with your real SQLite `users` table
  lookup, with real password hashing (the stub uses plaintext - fine
  for demo, not for anything real).
- Replace the in-memory `_session` dict in `session.py` with your real
  session store.
- Keep every permission name in `rbac.py`'s `PERMISSIONS` table exactly
  as spelled in `Role2.docx`, **except one addition**:
  `VALIDATE_SANITIZATION` (ADMIN, OPERATOR) - not in your original
  doc. Person 1 added it so an Operator can run a quick post-wipe
  check right on the Device page without needing full
  `RECOVER_FILES`/`VIEW_RECOVERY` access. **Please confirm this
  permission name and role list with the team** before final
  integration - it's the one deviation from your signed-off contract.
- `user_management.py` stubs `create_user`/`disable_user`/`enable_user`/
  `change_role`/`change_password`/`get_all_users` per your doc, but
  **no GUI screen calls them yet** - ask Person 1 if you want an Admin
  "Manage Users" tab added.

### Person 3 - Device Detection & Sanitization Engine
File: `backend/role3_sanitization.py`
- Proposed functions: `detect_devices()`, `get_device_details(path)`,
  `sanitize_device(device_path, method, user_id)`.
- **No written spec existed for this role** - confirm the function
  shapes with the team.
- Now enforces RBAC per `Role2.docx` section 6's example code:
  `detect_devices()` checks `DETECT_USB`; `sanitize_device()` checks
  `SANITIZE_USB`. Keep these checks in your real implementation.
- The **output event shape** sent to Role 6
  (`log_device_event` / `log_sanitization_event`) already matches
  `Role6_API_Contract.docx` exactly - don't change those dict keys.
- Note the added `operation_id` field in the sanitization event - not
  in the original Role 6 contract table, but it's what lets the
  Assurance Score correlate sanitization + verification + recovery
  results for the same operation. Keep it (or agree on another
  correlation key with Person 6).

### Person 4 - File/Folder Eraser & Verification
File: `backend/role4_file_ops.py`
- Proposed functions: `erase_files(paths, method, user_id)` and
  `verify_hash(target, target_type, pre_hash, user_id, operation_id=None)`.
- No written spec existed - confirm the shape with the team.
- `erase_files()` checks `ERASE_FILE` per `Role2.docx`. `verify_hash()`
  checks `ERASE_FILE` OR `SANITIZE_USB` - **this is Person 1's
  assumption**, since your doc has no permission specifically named
  for verification. Confirm with Person 2 whether that's the right
  call, or whether verification needs its own permission name.

### Person 5 - Forensics / Recovery
Folder: `backend/person5_final/`
- Fully specified in `Person_5_Forensics_Integration_Spec.docx` - the
  stub folder matches it exactly (function names, input/output shapes).
- Just replace the three files with your real pytsk3/Scalpel/Foremost
  implementation. Keep `run_full_recovery`, `score_batch`,
  `run_post_wipe_scan`, and `to_audit_event` as the entry points.
- Your spec doesn't mention permission checks internally - per
  `Role2.docx` section 6, the calling code should check
  `RECOVER_FILES`/`VIEW_RECOVERY` before calling you. Person 1's GUI
  already does this at the call site (`recovery_page.py` and
  `device_page.py`), so you don't need to add it yourself unless you
  want defense in depth.
- One addition on the GUI side: after calling `to_audit_event(result)`,
  the recovery page adds an `operation_id` key to the dict before
  logging it to Role 6, for correlation. No change needed on your end.

### Person 6 - Trust Layer
File: `backend/role6_trust.py`
- Fully specified in `Role6_API_Contract.docx` - the stub implements
  every function in that contract, including a real (in-memory)
  SHA-256 hash chain so the audit log is genuinely tamper-evident.
- Now enforces RBAC: `get_audit_log()`, `verify_chain_integrity()`,
  `get_assurance_score()`, and `export_audit_log_json()` check
  `VIEW_AUDIT`; `generate_certificate()` and `generate_forensic_report()`
  check `GENERATE_REPORT`. **Note:** `Role2.docx` doesn't name a
  permission specifically for assurance scores - Person 1 gated
  `get_assurance_score()` on `VIEW_AUDIT` as a reasonable guess.
  Confirm with Person 2.
- Replace the in-memory `_AUDIT_LOG`/`_OPERATIONS` storage with your
  SQLite-backed tables, and replace the plain-text placeholder
  certificate/report writers with real PDF generation (e.g. `reportlab`).
- Keep every function name and return shape identical.

## 4. Running it today

```bash
cd sih_project
python3 main.py
```

Demo logins (defined in `backend/auth/login.py`):

| Username | Password | Role | Sees |
|---|---|---|---|
| `admin` | `Admin@123456` | ADMIN | Everything |
| `operator1` | `Operator@123` | OPERATOR | Device (with Sanitize + quick Post-Wipe Validation), File Eraser, Verification |
| `investigator1` | `Investigator@123` | INVESTIGATOR | Device (view-only), Recovery/Carving, Assurance & Audit, Reports/Certificates |

Suggested demo flow: log in as `admin` -> Device page -> scan -> wipe
a device -> copy the generated `operation_id` -> Recovery page -> run
recovery scan + post-wipe validation -> Assurance page -> get score ->
Reports page -> generate certificate. Then log out and log back in as
`operator1` or `investigator1` to see the RBAC-restricted views.

## 5. Known gaps to close before the final build

1. Roles 3 and 4 have no written integration spec (unlike Roles 2, 5,
   and 6) - confirm those interfaces with the team the same way the
   other three were confirmed.
2. `VALIDATE_SANITIZATION` permission and the `operation_id`
   correlation field are Person 1 additions, not in the original
   docs - flag both in your next sync so everyone agrees on them (or
   on alternatives).
3. PDF generation in Role 6 is currently a plain-text placeholder, not
   an actual PDF.
4. `user_management.py` (create/disable/enable users, change role,
   change password) has no GUI screen yet - only needed if an Admin
   "Manage Users" tab gets built.
