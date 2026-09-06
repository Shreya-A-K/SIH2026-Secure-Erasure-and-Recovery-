import tkinter as tk
from tkinter import ttk, messagebox

from backend.person5_final.recovery_engine import run_full_recovery
from backend.person5_final.post_wipe_validation import run_post_wipe_scan, to_audit_event
from backend import role6_trust
from backend.auth.rbac import has_permission
from gui.theme import COLORS, FONTS


class RecoveryPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        form_card = ttk.Frame(self, style="Card.TFrame", padding=20)
        form_card.pack(fill="x")

        form = ttk.Frame(form_card, style="Card.TFrame")
        form.pack(fill="x")

        ttk.Label(form, text="Operation ID:", background=COLORS["card"]).grid(row=0, column=0, sticky="w", pady=3)
        self.op_id_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.op_id_var, width=25).grid(row=0, column=1, sticky="w", padx=(10, 0))
        ttk.Button(form, text="Use last operation", command=self._use_last_op).grid(row=0, column=2, padx=(10, 0))

        ttk.Label(form, text="Device path:", background=COLORS["card"]).grid(row=1, column=0, sticky="w", pady=3)
        self.device_var = tk.StringVar(value="./test.img")
        ttk.Entry(form, textvariable=self.device_var, width=25).grid(row=1, column=1, sticky="w", padx=(10, 0))

        ttk.Label(form, text="Scan type:", background=COLORS["card"]).grid(row=2, column=0, sticky="w", pady=3)
        self.scan_type_var = tk.StringVar(value="FULL")
        ttk.Combobox(form, textvariable=self.scan_type_var, values=["QUICK", "FULL"],
                     state="readonly", width=10).grid(row=2, column=1, sticky="w", padx=(10, 0))

        btn_row = ttk.Frame(form_card, style="Card.TFrame")
        btn_row.pack(anchor="w", pady=(16, 0))
        ttk.Button(btn_row, text="Run Recovery Scan", style="Accent.TButton",
                   command=self._run_recovery).pack(side="left")
        ttk.Button(btn_row, text="Run Post-Wipe Validation",
                   command=self._run_validation).pack(side="left", padx=(8, 0))

        ttk.Label(self, text="Recovered Files", style="Muted.TLabel", font=FONTS["small"]).pack(
            anchor="w", pady=(16, 4)
        )
        tree_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        tree_card.pack(fill="both", expand=True)
        columns = ("name", "method", "size", "confidence_score", "confidence_label")
        self.tree = ttk.Treeview(tree_card, columns=columns, show="headings", height=6)
        for col, label in zip(columns, ("Name", "Method", "Size (bytes)", "Confidence", "Label")):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=130)
        self.tree.pack(fill="both", expand=True, padx=1, pady=1)

        self.status_label = ttk.Label(self, text="", font=FONTS["label_bold"])
        self.status_label.pack(anchor="w", pady=(10, 0))

    def on_show(self):
        pass

    def _use_last_op(self):
        if self.controller.last_operation_id:
            self.op_id_var.set(self.controller.last_operation_id)
        else:
            messagebox.showinfo("No operation yet", "Sanitize a device first to generate an operation_id.")

    def _run_recovery(self):
        # Person 5's module doesn't check permissions itself (see
        # Person_5_Forensics_Integration_Spec.docx) - Role2.docx section
        # 6 shows this check belongs at the calling site, so it's done
        # here. Tab is already gated on VIEW_RECOVERY, so this normally
        # never fires - it's defense in depth per Role2.docx section 7.
        if not has_permission("RECOVER_FILES"):
            messagebox.showerror("Access denied", "RECOVER_FILES permission required.")
            return

        request = {
            "operation_id": self.op_id_var.get() or "OP-MANUAL",
            "device_path": self.device_var.get(),
            "scan_type": self.scan_type_var.get(),
            "file_types": ["jpg", "png", "pdf"],
            "output_dir": "./recovered",
        }
        result = run_full_recovery(request)

        for row in self.tree.get_children():
            self.tree.delete(row)
        for f in result["files"]:
            self.tree.insert("", "end", values=(f["name"], f["method"], f["size"],
                                                 f["confidence_score"], f["confidence_label"]))

        self.status_label.config(
            text=f"Recovery {result['status']} - {result['files_found']} file(s) found.",
            foreground=COLORS["success"],
        )

    def _run_validation(self):
        if not has_permission("VIEW_RECOVERY"):
            messagebox.showerror("Access denied", "VIEW_RECOVERY permission required.")
            return

        op_id = self.op_id_var.get() or "OP-MANUAL"
        request = {
            "operation_id": op_id,
            "device_path": self.device_var.get(),
            "sanitization_status": "SUCCESS",
            "method": "OVERWRITE",
        }
        result = run_post_wipe_scan(request)
        audit_event = to_audit_event(result)
        audit_event["operation_id"] = op_id  # extra field for Role 6 correlation - see role3/role4 stubs
        role6_trust.log_recovery_validation_event(audit_event)

        color = COLORS["success"] if result["validation_status"] == "PASS" else COLORS["danger"]
        self.status_label.config(
            text=f"Post-wipe validation: {result['validation_status']} "
                 f"({result['qualifying_artifacts']} qualifying artifacts)",
            foreground=color,
        )
