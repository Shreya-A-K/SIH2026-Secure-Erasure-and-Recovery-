import tkinter as tk
from tkinter import ttk, messagebox

import role3_sanitization
from auth.rbac import has_permission
from person5_final.post_wipe_validation import run_post_wipe_scan, to_audit_event
from api import get_trust_layer
from gui.theme import COLORS, FONTS
from gui.async_runner import AsyncRunner


class DevicePage(ttk.Frame):
    """
    Device Detection, Information, Sanitization Recommendation & Safe Wipe.
    Integrated with Role 2 RBAC, Role 3 Sanitization, Role 5 Post-Wipe Validation, and Role 6 TrustLayer.
    """

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.selected_device = None
        self.device_cache = {}
        self.is_busy = False
        self.runner = AsyncRunner(self)

        scan_row = ttk.Frame(self)
        scan_row.pack(fill="x", pady=(0, 10))

        ttk.Button(scan_row, text="\U0001F50E  Scan for Devices", style="Accent.TButton",
                   command=self._scan).pack(side="left")
        self.scan_status_label = ttk.Label(scan_row, text="Click scan to detect available targets",
                                           style="Muted.TLabel")
        self.scan_status_label.pack(side="left", padx=(14, 0))

        tree_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        tree_card.pack(fill="x")
        columns = ("device_path", "model", "capacity_gb", "filesystem")
        self.tree = ttk.Treeview(tree_card, columns=columns, show="headings", height=4)
        for col, label in zip(columns, ("Path", "Model", "Capacity (GB)", "Filesystem")):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=160)
        self.tree.pack(fill="x", padx=1, pady=1)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # ---- Device Information & Recommendation Panel -----------------
        self.info_card = ttk.LabelFrame(self, text="Device Information & Recommendation",
                                       style="Card.TLabelframe", padding=12)
        self.info_card.pack(fill="x", pady=(10, 0))

        self.info_label = ttk.Label(
            self.info_card,
            text="No target selected. Select a device from the list above.",
            background=COLORS["card"], font=FONTS["label"]
        )
        self.info_label.pack(anchor="w")

        self.rec_label = ttk.Label(
            self.info_card,
            text="Recommended Method: —",
            background=COLORS["card"], foreground=COLORS["accent"], font=FONTS["label_bold"]
        )
        self.rec_label.pack(anchor="w", pady=(4, 0))

        # ---- Sanitize panel & Validation panel --------------------------
        self.panels_container = ttk.Frame(self)
        self.panels_container.pack(fill="x")

        self.sanitize_frame = ttk.LabelFrame(self.panels_container, text="Sanitize Selected Device",
                                              style="Card.TLabelframe", padding=14)
        ttk.Label(self.sanitize_frame, text="Method:", background=COLORS["card"]).grid(
            row=0, column=0, sticky="w"
        )
        self.method_var = tk.StringVar(value=role3_sanitization.SANITIZATION_METHODS[0])
        ttk.Combobox(
            self.sanitize_frame, textvariable=self.method_var,
            values=role3_sanitization.SANITIZATION_METHODS, state="readonly", width=32,
        ).grid(row=0, column=1, sticky="w", padx=(10, 0))
        self.wipe_btn = ttk.Button(self.sanitize_frame, text="Wipe Device (Safe)", style="Danger.TButton",
                                  command=self._sanitize)
        self.wipe_btn.grid(row=0, column=2, padx=(20, 0))

        # ---- Post-wipe validation panel ---------------------------------
        self.validate_frame = ttk.LabelFrame(self.panels_container, text="Post-Wipe Forensic Validation",
                                              style="Card.TLabelframe", padding=14)
        ttk.Label(self.validate_frame, text="Quick validation: Verify whether any recoverable artifacts remain.",
                  background=COLORS["card"], foreground=COLORS["text_muted"]).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        self.val_btn = ttk.Button(self.validate_frame, text="Run Quick Validation",
                                 command=self._run_quick_validation)
        self.val_btn.grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.validate_result_label = ttk.Label(self.validate_frame, text="", background=COLORS["card"])
        self.validate_result_label.grid(row=1, column=1, sticky="w", padx=(12, 0), pady=(8, 0))

        # ---- Activity Log -----------------------------------------------
        ttk.Label(self, text="Activity Log", style="Muted.TLabel", font=FONTS["small"]).pack(
            anchor="w", pady=(10, 2)
        )
        log_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        log_card.pack(fill="both", expand=True)
        self.result_text = tk.Text(log_card, height=6, wrap="word", relief="flat", bd=0,
                                    font=FONTS["mono"], padx=10, pady=8)
        self.result_text.pack(fill="both", expand=True)
        self.result_text.configure(state="disabled")

    def on_show(self):
        self.sanitize_frame.pack_forget()
        self.validate_frame.pack_forget()

        if has_permission("SANITIZE_USB"):
            self.sanitize_frame.pack(fill="x", pady=(10, 0))
        if has_permission("SANITIZE_USB") or has_permission("VIEW_RECOVERY"):
            self.validate_frame.pack(fill="x", pady=(10, 0))

        # Automatically scan if list is empty
        if not self.tree.get_children():
            self._scan()

    def _scan(self):
        try:
            for row in self.tree.get_children():
                self.tree.delete(row)
            devices = role3_sanitization.detect_devices()
            self.device_cache = {d["device_path"]: d for d in devices}
            for d in devices:
                self.tree.insert("", "end", iid=d["device_path"],
                                  values=(d["device_path"], d["model"], d["capacity_gb"], d["filesystem"]))
            self.scan_status_label.config(text=f"Detected {len(devices)} target(s)")
            self._log(f"Scan complete: Found {len(devices)} safe target(s).")
            if devices:
                first = devices[0]["device_path"]
                self.tree.selection_set(first)
                self._on_select(None)
        except Exception as e:
            self._log(f"Detection error: {e}")
            messagebox.showerror("Scan Error", f"Error detecting devices: {e}")

    def _on_select(self, _event):
        selection = self.tree.selection()
        if not selection:
            self.selected_device = None
            self.info_label.config(text="No target selected.")
            self.rec_label.config(text="Recommended Method: —")
            return

        self.selected_device = selection[0]
        dev_info = self.device_cache.get(self.selected_device, {})
        model = dev_info.get("model", "Unknown")
        fs = dev_info.get("filesystem", "Unknown")
        cap = dev_info.get("capacity_gb", "Unknown")
        serial = dev_info.get("serial", "N/A")

        rec = role3_sanitization.recommend_method(self.selected_device)
        self.info_label.config(
            text=f"Path: {self.selected_device}  |  Model: {model}  |  Size: {cap} GB  |  FS: {fs}  |  Serial: {serial}"
        )
        self.rec_label.config(text=f"Recommended Method: {rec}")
        if rec in role3_sanitization.SANITIZATION_METHODS:
            self.method_var.set(rec)

    def _sanitize(self):
        if self.is_busy:
            messagebox.showwarning("Busy", "An operation is currently in progress.")
            return

        if not self.selected_device:
            messagebox.showwarning("No target selected", "Please select a target device from the list.")
            return

        method = self.method_var.get()
        confirmed = messagebox.askyesno(
            "Confirm Wipe",
            f"This will PERMANENTLY sanitize all data on:\n\n{self.selected_device}\n\n"
            f"Using standard: {method}.\n\n"
            "This action cannot be undone. Do you wish to proceed?",
        )
        if not confirmed:
            self._log("Sanitization cancelled by user.")
            return

        self.is_busy = True
        self.wipe_btn.configure(state="disabled")
        self._log(f"Starting sanitization on {self.selected_device} with {method}...")

        user_id = self.controller.session.get("username") or self.controller.session.get("user_id", "unknown")
        target = self.selected_device
        method_to_use = method

        self.runner.run(
            task_fn=lambda: role3_sanitization.sanitize_device(target, method_to_use, user_id),
            on_complete=self._on_sanitize_complete,
            on_error=self._on_sanitize_error,
        )

    def _on_sanitize_complete(self, result):
        self.is_busy = False
        self.wipe_btn.configure(state="normal")

        if result.get("authorized") is False:
            messagebox.showerror("Access Denied", result.get("reason", "Unauthorized operation."))
            self._log(f"Sanitization blocked: {result.get('reason')}")
            return

        if result.get("status") != "SUCCESS":
            messagebox.showerror("Sanitization Failed", result.get("reason", "Unknown failure."))
            self._log(f"Sanitization failed: {result.get('reason')}")
            return

        op_id = result.get("operation_id")
        self.controller.last_operation_id = op_id
        self.controller.last_device_path = self.selected_device

        self._log(
            f"SANIZATION SUCCESSFUL!\n"
            f"  - Target:       {self.selected_device}\n"
            f"  - Method:       {result.get('method')}\n"
            f"  - Operation ID: {op_id}\n"
            f"  - Pre-SHA256:   {result.get('pre_hash', '')[:16]}...\n"
            f"  - Post-SHA256:  {result.get('post_hash', '')[:16]}...\n"
            f"-> Context propagated to Verification, Post-Wipe Validation, Assurance, and Reports pages."
        )
        messagebox.showinfo(
            "Sanitization Complete",
            f"Device successfully sanitized.\nOperation ID: {op_id}\n\n"
            "You may now proceed to Verification or Post-Wipe Validation."
        )

    def _on_sanitize_error(self, err_msg):
        self.is_busy = False
        self.wipe_btn.configure(state="normal")
        self._log(f"Sanitization execution error: {err_msg}")
        messagebox.showerror("Sanitization Error", f"An error occurred during sanitization:\n{err_msg}")

    def _run_quick_validation(self):
        if self.is_busy:
            messagebox.showwarning("Busy", "An operation is currently in progress.")
            return

        op_id = self.controller.last_operation_id
        target = self.controller.last_device_path or self.selected_device

        if not op_id or not target:
            messagebox.showinfo("No Operation Yet", "Sanitize a target first to generate an operation context.")
            return

        self.is_busy = True
        self.val_btn.configure(state="disabled")
        self.validate_result_label.config(text="Scanning for residual artifacts...", foreground=COLORS["accent"])
        self._log(f"Starting quick post-wipe validation for operation {op_id} on {target}...")

        request = {
            "operation_id": op_id,
            "device_path": target,
            "scope": "quick",
        }

        def validate_task():
            res = run_post_wipe_scan(request)
            audit_event = to_audit_event(res)
            audit_event["operation_id"] = op_id
            tl = get_trust_layer()
            tl.log_recovery_validation_event(audit_event)
            return res

        self.runner.run(
            task_fn=validate_task,
            on_complete=self._on_validation_complete,
            on_error=self._on_validation_error,
        )

    def _on_validation_complete(self, result):
        self.is_busy = False
        self.val_btn.configure(state="normal")

        verdict = result.get("validation_status") or result.get("verdict", "PASS")
        qualifying = result.get("qualifying_artifacts", 0)

        color = COLORS["success"] if verdict == "PASS" else COLORS["danger"]
        self.validate_result_label.config(
            text=f"Verdict: {verdict} ({qualifying} residual artifacts above threshold)",
            foreground=color,
        )
        self._log(f"Post-wipe validation: {verdict} | Qualifying artifacts: {qualifying}")
        messagebox.showinfo(
            "Validation Completed",
            f"Post-Wipe Validation Result: {verdict}\n"
            f"Residual qualifying artifacts: {qualifying}\n"
            "Recorded in hash chain audit log."
        )

    def _on_validation_error(self, err_msg):
        self.is_busy = False
        self.val_btn.configure(state="normal")
        self.validate_result_label.config(text="Validation error", foreground=COLORS["danger"])
        self._log(f"Post-wipe validation error: {err_msg}")
        messagebox.showerror("Validation Error", f"Post-wipe validation failed:\n{err_msg}")

    def _log(self, message):
        self.result_text.configure(state="normal")
        self.result_text.insert("end", message + "\n")
        self.result_text.see("end")
        self.result_text.configure(state="disabled")
