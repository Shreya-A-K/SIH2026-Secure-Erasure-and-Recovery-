import os
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from backend import role6_trust
from gui.theme import COLORS, FONTS


def _open_path(path):
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except OSError:
        messagebox.showinfo("File generated", f"Saved to:\n{path}")


class ReportsPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        top = ttk.Frame(self, style="Card.TFrame", padding=20)
        top.pack(fill="x")
        ttk.Label(top, text="Operation ID:", background=COLORS["card"]).grid(row=0, column=0, sticky="w")
        self.op_id_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.op_id_var, width=18).grid(row=0, column=1, padx=(10, 0))
        ttk.Button(top, text="Use last", command=self._use_last_op).grid(row=0, column=2, padx=(10, 0))

        btn_row = ttk.Frame(self)
        btn_row.pack(fill="x", pady=16)
        ttk.Button(btn_row, text="\U0001F4DC  Generate Certificate", style="Accent.TButton",
                   command=self._gen_certificate).pack(side="left")
        ttk.Button(btn_row, text="\U0001F4C4  Generate Forensic Report",
                   command=self._gen_report).pack(side="left", padx=(8, 0))
        ttk.Button(btn_row, text="\u2B07  Export Audit Log (JSON)",
                   command=self._export_json).pack(side="left", padx=(8, 0))

        ttk.Label(self, text="Activity Log", style="Muted.TLabel", font=FONTS["small"]).pack(anchor="w")
        log_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        log_card.pack(fill="both", expand=True, pady=(4, 0))
        self.result_text = tk.Text(log_card, height=10, wrap="word", relief="flat", bd=0,
                                    font=FONTS["mono"], padx=10, pady=8)
        self.result_text.pack(fill="both", expand=True)
        self.result_text.configure(state="disabled")

    def on_show(self):
        pass

    def _use_last_op(self):
        if self.controller.last_operation_id:
            self.op_id_var.set(self.controller.last_operation_id)

    def _get_op_id(self):
        op_id = self.op_id_var.get()
        if not op_id:
            self._use_last_op()
            op_id = self.op_id_var.get()
        if not op_id:
            messagebox.showwarning("Missing operation ID", "Enter or select an operation_id first.")
        return op_id

    def _gen_certificate(self):
        op_id = self._get_op_id()
        if not op_id:
            return
        path = role6_trust.generate_certificate(op_id)
        if not path:
            messagebox.showerror("Access denied", "GENERATE_REPORT permission required.")
            return
        self._log(f"Certificate generated: {path}")
        _open_path(path)

    def _gen_report(self):
        op_id = self._get_op_id()
        if not op_id:
            return
        path = role6_trust.generate_forensic_report(op_id)
        if not path:
            messagebox.showerror("Access denied", "GENERATE_REPORT permission required.")
            return
        self._log(f"Forensic report generated: {path}")
        _open_path(path)

    def _export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile="audit_log.json")
        if not path:
            return
        success = role6_trust.export_audit_log_json(path)
        self._log(f"Audit log export {'succeeded' if success else 'FAILED'}: {path}")

    def _log(self, message):
        self.result_text.configure(state="normal")
        self.result_text.insert("end", message + "\n")
        self.result_text.see("end")
        self.result_text.configure(state="disabled")
