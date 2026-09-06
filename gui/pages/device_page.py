import tkinter as tk
from tkinter import ttk, messagebox

from backend import role3_sanitization
from backend.auth.rbac import has_permission
from backend.person5_final.post_wipe_validation import run_post_wipe_scan, to_audit_event
from backend import role6_trust
from gui.theme import COLORS, FONTS


class DevicePage(ttk.Frame):
    """
    Shown to anyone with DETECT_USB (ADMIN, OPERATOR, INVESTIGATOR - see
    Role2.docx). Everyone sees the device list. Two sub-panels below it
    are shown/hidden per-role in on_show(), not just disabled, so an
    Investigator genuinely does not see sanitize controls:

      - "Sanitize Selected Device"  - needs SANITIZE_USB (ADMIN, OPERATOR)
      - "Post-Wipe Validation"      - needs VALIDATE_SANITIZATION
                                      (ADMIN, OPERATOR - a Person 1
                                      addition, see rbac.py)

    An Investigator instead uses the full Recovery / Carving tab, which
    is gated separately on VIEW_RECOVERY.
    """

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.selected_device = None

        ttk.Button(self, text="\U0001F50E  Scan for Devices", style="Accent.TButton",
                   command=self._scan).pack(anchor="w", pady=(0, 12))

        tree_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        tree_card.pack(fill="x")
        columns = ("device_path", "model", "capacity_gb", "filesystem")
        self.tree = ttk.Treeview(tree_card, columns=columns, show="headings", height=5)
        for col, label in zip(columns, ("Path", "Model", "Capacity (GB)", "Filesystem")):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=160)
        self.tree.pack(fill="x", padx=1, pady=1)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # ---- Sanitize panel (SANITIZE_USB only) - built once, packed
        # conditionally in on_show() ---------------------------------
        self.panels_container = ttk.Frame(self)
        self.panels_container.pack(fill="x")

        self.sanitize_frame = ttk.LabelFrame(self.panels_container, text="Sanitize Selected Device",
                                              style="Card.TLabelframe", padding=16)
        ttk.Label(self.sanitize_frame, text="Method:", background=COLORS["card"]).grid(
            row=0, column=0, sticky="w"
        )
        self.method_var = tk.StringVar(value=role3_sanitization.SANITIZATION_METHODS[0])
        ttk.Combobox(
            self.sanitize_frame, textvariable=self.method_var,
            values=role3_sanitization.SANITIZATION_METHODS, state="readonly", width=20,
        ).grid(row=0, column=1, sticky="w", padx=(10, 0))
        ttk.Button(self.sanitize_frame, text="Wipe Device", style="Danger.TButton",
                   command=self._sanitize).grid(row=0, column=2, padx=(20, 0))

        # ---- Post-wipe validation panel (VALIDATE_SANITIZATION only) -
        self.validate_frame = ttk.LabelFrame(self.panels_container, text="Post-Wipe Validation",
                                              style="Card.TLabelframe", padding=16)
        ttk.Label(self.validate_frame, text="Quick check: is anything still recoverable "
                                             "from your last wipe?", background=COLORS["card"],
                  foreground=COLORS["text_muted"]).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Button(self.validate_frame, text="Run Quick Validation",
                   command=self._run_quick_validation).grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.validate_result_label = ttk.Label(self.validate_frame, text="", background=COLORS["card"])
        self.validate_result_label.grid(row=1, column=1, sticky="w", padx=(12, 0), pady=(10, 0))

        ttk.Label(self, text="Activity Log", style="Muted.TLabel", font=FONTS["small"]).pack(anchor="w")
        log_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        log_card.pack(fill="both", expand=True, pady=(4, 0))
        self.result_text = tk.Text(log_card, height=8, wrap="word", relief="flat", bd=0,
                                    font=FONTS["mono"], padx=10, pady=8)
        self.result_text.pack(fill="both", expand=True)
        self.result_text.configure(state="disabled")

    def on_show(self):
        # Re-evaluate every time the tab is shown, since a different
        # role may be logged in now than when this frame was built.
        self.sanitize_frame.pack_forget()
        self.validate_frame.pack_forget()

        if has_permission("SANITIZE_USB"):
            self.sanitize_frame.pack(fill="x", pady=(16, 0))
        if has_permission("VALIDATE_SANITIZATION"):
            self.validate_frame.pack(fill="x", pady=(16, 0))

    def _scan(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        devices = role3_sanitization.detect_devices()
        for d in devices:
            self.tree.insert("", "end", iid=d["device_path"],
                              values=(d["device_path"], d["model"], d["capacity_gb"], d["filesystem"]))
        self._log(f"Found {len(devices)} removable device(s).")

    def _on_select(self, _event):
        selection = self.tree.selection()
        self.selected_device = selection[0] if selection else None

    def _sanitize(self):
        if not self.selected_device:
            messagebox.showwarning("No device selected", "Select a device from the list first.")
            return

        method = self.method_var.get()
        confirmed = messagebox.askyesno(
            "Confirm wipe",
            f"This will PERMANENTLY erase all data on {self.selected_device} using {method}.\n\n"
            "This cannot be undone. Continue?",
        )
        if not confirmed:
            return

        user_id = self.controller.session.get("user_id", "unknown")
        result = role3_sanitization.sanitize_device(self.selected_device, method, user_id)

        if result.get("authorized") is False:
            messagebox.showerror("Access denied", result.get("reason", "You don't have permission to do this."))
            return

        self.controller.last_operation_id = result["operation_id"]
        self.controller.last_device_path = self.selected_device
        self._log(
            f"Sanitization {result['sanitization_status']} - operation_id = {result['operation_id']}\n"
            f"Tip: use this operation_id in Assurance / Reports pages next, or run a quick "
            f"validation below."
        )

    def _run_quick_validation(self):
        if not self.controller.last_operation_id:
            messagebox.showinfo("No operation yet", "Sanitize a device first.")
            return

        request = {
            "operation_id": self.controller.last_operation_id,
            "device_path": self.controller.last_device_path or self.selected_device,
            "sanitization_status": "SUCCESS",
            "method": "OVERWRITE",
        }
        result = run_post_wipe_scan(request)
        audit_event = to_audit_event(result)
        audit_event["operation_id"] = self.controller.last_operation_id
        role6_trust.log_recovery_validation_event(audit_event)

        color = COLORS["success"] if result["validation_status"] == "PASS" else COLORS["danger"]
        self.validate_result_label.config(
            text=f"{result['validation_status']} ({result['qualifying_artifacts']} qualifying artifacts)",
            foreground=color,
        )
        self._log(f"Post-wipe validation: {result['validation_status']}")

    def _log(self, message):
        self.result_text.configure(state="normal")
        self.result_text.insert("end", message + "\n")
        self.result_text.see("end")
        self.result_text.configure(state="disabled")
