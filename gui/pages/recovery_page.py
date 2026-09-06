import tkinter as tk
from tkinter import ttk, messagebox

from person5_final.recovery_engine import run_full_recovery
from person5_final.post_wipe_validation import run_post_wipe_scan, to_audit_event
from api import get_trust_layer
from auth.rbac import has_permission
from gui.theme import COLORS, FONTS
from gui.async_runner import AsyncRunner


class RecoveryPage(ttk.Frame):
    """
    Role 5: Forensic Recovery & Carving.
    Features:
      - Deep signature carving (Scalpel/Foremost) and filesystem metadata recovery (TSK).
      - Explainable Recovery Confidence Score for each recovered artifact.
      - Post-wipe forensic validation.
      - Audit event logging into Role 6 TrustLayer.
    """

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.is_busy = False
        self.runner = AsyncRunner(self)

        form_card = ttk.Frame(self, style="Card.TFrame", padding=20)
        form_card.pack(fill="x")

        form = ttk.Frame(form_card, style="Card.TFrame")
        form.pack(fill="x")

        ttk.Label(form, text="Operation ID:", background=COLORS["card"]).grid(row=0, column=0, sticky="w", pady=3)
        self.op_id_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.op_id_var, width=25).grid(row=0, column=1, sticky="w", padx=(10, 0))
        ttk.Button(form, text="Use last operation", command=self._use_last_op).grid(row=0, column=2, padx=(10, 0))

        ttk.Label(form, text="Device path:", background=COLORS["card"]).grid(row=1, column=0, sticky="w", pady=3)
        self.device_var = tk.StringVar(value="test_data/test.img")
        ttk.Entry(form, textvariable=self.device_var, width=35).grid(row=1, column=1, sticky="w", padx=(10, 0))

        ttk.Label(form, text="Scan type:", background=COLORS["card"]).grid(row=2, column=0, sticky="w", pady=3)
        self.scan_type_var = tk.StringVar(value="FULL")
        ttk.Combobox(form, textvariable=self.scan_type_var, values=["QUICK", "FULL"],
                     state="readonly", width=10).grid(row=2, column=1, sticky="w", padx=(10, 0))

        btn_row = ttk.Frame(form_card, style="Card.TFrame")
        btn_row.pack(anchor="w", pady=(16, 0))
        self.rec_btn = ttk.Button(btn_row, text="Run Recovery Scan", style="Accent.TButton",
                                 command=self._run_recovery)
        self.rec_btn.pack(side="left")
        self.val_btn = ttk.Button(btn_row, text="Run Post-Wipe Validation",
                                 command=self._run_validation)
        self.val_btn.pack(side="left", padx=(8, 0))

        ttk.Label(self, text="Recovered Files & Confidence Scores", style="Muted.TLabel", font=FONTS["small"]).pack(
            anchor="w", pady=(16, 4)
        )
        tree_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        tree_card.pack(fill="both", expand=True)
        columns = ("name", "method", "size", "confidence_score", "confidence_label")
        self.tree = ttk.Treeview(tree_card, columns=columns, show="headings", height=6)
        for col, label, width in zip(columns, ("Name", "Method", "Size (bytes)", "Confidence Score", "Label"), (160, 100, 100, 120, 100)):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True, padx=1, pady=1)

        self.status_label = ttk.Label(self, text="", font=FONTS["label_bold"])
        self.status_label.pack(anchor="w", pady=(10, 0))

    def on_show(self):
        if not self.op_id_var.get() and self.controller.last_operation_id:
            self._use_last_op()

    def _use_last_op(self):
        if self.controller.last_operation_id:
            self.op_id_var.set(self.controller.last_operation_id)
        if getattr(self.controller, "last_device_path", None):
            self.device_var.set(self.controller.last_device_path)
        elif not self.controller.last_operation_id:
            messagebox.showinfo("No operation yet", "Sanitize a target first to generate an operation_id.")

    def _run_recovery(self):
        if self.is_busy:
            messagebox.showwarning("Busy", "An operation is currently in progress.")
            return

        if not has_permission("RECOVER_FILES"):
            messagebox.showerror("Access denied", "RECOVER_FILES permission required.")
            return

        device_path = self.device_var.get().strip()
        if not device_path:
            messagebox.showwarning("Missing path", "Please specify a target image or file path.")
            return

        self.is_busy = True
        self.rec_btn.configure(state="disabled")
        self.status_label.config(text="Running deep recovery scan & file carving...", foreground=COLORS["accent"])

        request = {
            "operation_id": self.op_id_var.get() or "OP-MANUAL",
            "device_path": device_path,
            "scan_type": self.scan_type_var.get(),
            "file_types": ["jpg", "png", "pdf", "txt"],
            "output_dir": "./recovered",
        }

        self.runner.run(
            task_fn=lambda: run_full_recovery(request),
            on_complete=self._on_recovery_complete,
            on_error=self._on_recovery_error,
        )

    def _on_recovery_complete(self, result):
        self.is_busy = False
        self.rec_btn.configure(state="normal")

        for row in self.tree.get_children():
            self.tree.delete(row)

        files = result.get("files", [])
        for f in files:
            self.tree.insert("", "end", values=(f["name"], f["method"], f["size"],
                                                 f"{f['confidence_score']}/100", f["confidence_label"]))

        count = len(files)
        status_str = f"Recovery {result.get('status', 'COMPLETED')} — {count} artifact(s) found."
        self.status_label.config(
            text=status_str,
            foreground=COLORS["success"] if count > 0 else COLORS["text_muted"],
        )
        messagebox.showinfo("Recovery Scan Complete", f"{status_str}\nEach artifact scored with explainable confidence.")

    def _on_recovery_error(self, err_msg):
        self.is_busy = False
        self.rec_btn.configure(state="normal")
        self.status_label.config(text=f"Recovery failed: {err_msg}", foreground=COLORS["danger"])
        messagebox.showerror("Recovery Error", f"Failed to complete recovery scan:\n{err_msg}")

    def _run_validation(self):
        if self.is_busy:
            messagebox.showwarning("Busy", "An operation is currently in progress.")
            return

        if not has_permission("VIEW_RECOVERY"):
            messagebox.showerror("Access denied", "VIEW_RECOVERY permission required.")
            return

        device_path = self.device_var.get().strip()
        if not device_path:
            messagebox.showwarning("Missing path", "Please specify a target image or file path.")
            return

        op_id = self.op_id_var.get().strip() or "OP-MANUAL"
        self.is_busy = True
        self.val_btn.configure(state="disabled")
        self.status_label.config(text="Running forensic post-wipe validation...", foreground=COLORS["accent"])

        request = {
            "operation_id": op_id,
            "device_path": device_path,
            "sanitization_status": "SUCCESS",
            "method": "OVERWRITE",
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
        self.status_label.config(
            text=f"Post-wipe validation: {verdict} ({qualifying} residual qualifying artifacts)",
            foreground=color,
        )
        messagebox.showinfo(
            "Validation Completed",
            f"Post-Wipe Validation Verdict: {verdict}\n"
            f"Qualifying Artifacts: {qualifying}\n"
            "Logged into hash chain audit log."
        )

    def _on_validation_error(self, err_msg):
        self.is_busy = False
        self.val_btn.configure(state="normal")
        self.status_label.config(text=f"Validation failed: {err_msg}", foreground=COLORS["danger"])
        messagebox.showerror("Validation Error", f"Failed to complete post-wipe validation:\n{err_msg}")
