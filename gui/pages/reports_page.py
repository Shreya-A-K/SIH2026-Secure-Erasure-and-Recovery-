import os
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from api import get_trust_layer
from auth.rbac import has_permission
from gui.theme import COLORS, FONTS


def _open_path(path):
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except Exception:
        messagebox.showinfo("File Generated", f"Report saved to:\n{path}")


class ReportsPage(ttk.Frame):
    """
    Role 6: Reports and Official Sanitization / Forensic Certificates.
    Generates PDF Certificates and Forensic Evidence Reports.
    Exports cryptographic hash chain audit logs to JSON.
    """

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        top = ttk.Frame(self, style="Card.TFrame", padding=20)
        top.pack(fill="x")
        ttk.Label(top, text="Operation ID:", background=COLORS["card"]).grid(row=0, column=0, sticky="w")
        self.op_id_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.op_id_var, width=22).grid(row=0, column=1, padx=(10, 0))
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
        if not self.op_id_var.get() and self.controller.last_operation_id:
            self._use_last_op()

    def _use_last_op(self):
        if self.controller.last_operation_id:
            self.op_id_var.set(self.controller.last_operation_id)

    def _get_op_id(self):
        op_id = self.op_id_var.get().strip()
        if not op_id:
            self._use_last_op()
            op_id = self.op_id_var.get().strip()
        if not op_id:
            messagebox.showwarning("Missing Operation ID", "Please enter or select an Operation ID first.")
        return op_id

    def _gen_certificate(self):
        if not has_permission("GENERATE_REPORT"):
            messagebox.showerror("Access Denied", "GENERATE_REPORT permission required.")
            return

        op_id = self._get_op_id()
        if not op_id:
            return

        try:
            tl = get_trust_layer()
            path = tl.generate_certificate(op_id)
            self._log(f"Certificate generated successfully:\n  {path}")
            messagebox.showinfo("Certificate Generated", f"Certificate saved to:\n{path}")
            _open_path(path)
        except ValueError as e:
            self._log(f"Error: {e}")
            messagebox.showerror("Operation Not Found", str(e))
        except Exception as e:
            self._log(f"Generation error: {e}")
            messagebox.showerror("Certificate Error", f"Failed to generate certificate: {e}")

    def _gen_report(self):
        if not has_permission("GENERATE_REPORT"):
            messagebox.showerror("Access Denied", "GENERATE_REPORT permission required.")
            return

        op_id = self._get_op_id()
        if not op_id:
            return

        try:
            tl = get_trust_layer()
            path = tl.generate_forensic_report(op_id)
            self._log(f"Forensic report generated successfully:\n  {path}")
            messagebox.showinfo("Forensic Report Generated", f"Forensic report saved to:\n{path}")
            _open_path(path)
        except ValueError as e:
            self._log(f"Error: {e}")
            messagebox.showerror("Operation Not Found", str(e))
        except Exception as e:
            self._log(f"Generation error: {e}")
            messagebox.showerror("Report Error", f"Failed to generate forensic report: {e}")

    def _export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile="audit_log.json")
        if not path:
            return
        try:
            tl = get_trust_layer()
            success = tl.export_audit_log_json(path)
            if success:
                self._log(f"Audit log exported to: {path}")
                messagebox.showinfo("Export Successful", f"Audit log exported to:\n{path}")
            else:
                self._log(f"Audit log export failed for path: {path}")
                messagebox.showerror("Export Failed", f"Could not write audit log to:\n{path}")
        except Exception as e:
            self._log(f"Export error: {e}")
            messagebox.showerror("Export Error", f"Failed to export audit log: {e}")

    def _log(self, message):
        self.result_text.configure(state="normal")
        self.result_text.insert("end", message + "\n")
        self.result_text.see("end")
        self.result_text.configure(state="disabled")
