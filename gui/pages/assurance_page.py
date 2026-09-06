import tkinter as tk
from tkinter import ttk, messagebox

from api import get_trust_layer
from gui.theme import COLORS, FONTS

GRADE_COLORS = {
    "A+": COLORS["success"],
    "A": COLORS["success"],
    "B": COLORS["warning"],
    "C": COLORS["warning"],
    "F": COLORS["danger"],
}


class AssurancePage(ttk.Frame):
    """
    Role 6: Assurance Score & Cryptographic Hash Chain Audit.
    Evaluates multi-role evidence (sanitization, verification, recovery, audit integrity)
    into an explainable assurance grade and verifies immutable hash chain integrity.
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
        ttk.Button(top, text="Get Assurance Score", style="Accent.TButton", command=self._get_score).grid(
            row=0, column=3, padx=(10, 0)
        )

        score_card = ttk.Frame(self, style="Card.TFrame", padding=20)
        score_card.pack(fill="x", pady=(16, 0))
        self.score_label = tk.Label(score_card, text="\u2014", font=FONTS["score"], bg=COLORS["card"])
        self.score_label.pack(anchor="w")
        self.verdict_label = tk.Label(score_card, text="Enter or select an Operation ID to compute the assurance score.",
                                       font=FONTS["label_bold"], bg=COLORS["card"], fg=COLORS["text_muted"])
        self.verdict_label.pack(anchor="w", pady=(2, 10))
        self.breakdown_label = ttk.Label(score_card, text="", justify="left", background=COLORS["card"])
        self.breakdown_label.pack(anchor="w")

        audit_bar = ttk.Frame(self)
        audit_bar.pack(fill="x", pady=(20, 8))
        ttk.Label(audit_bar, text="Cryptographic Audit Log (Hash Chain)", style="Heading.TLabel").pack(side="left")
        ttk.Button(audit_bar, text="Refresh", command=self._refresh_log).pack(side="right")
        ttk.Button(audit_bar, text="Verify Chain Integrity", command=self._check_chain).pack(
            side="right", padx=(0, 8)
        )
        self.chain_label = ttk.Label(audit_bar, text="")
        self.chain_label.pack(side="right", padx=(0, 12))

        tree_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        tree_card.pack(fill="both", expand=True)
        columns = ("sequence", "event_type", "summary", "timestamp")
        self.tree = ttk.Treeview(tree_card, columns=columns, show="headings", height=10)
        for col, label, width in zip(columns, ("#", "Event", "Summary", "Timestamp"), (40, 160, 360, 180)):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True, padx=1, pady=1)

    def on_show(self):
        if not self.op_id_var.get() and self.controller.last_operation_id:
            self._use_last_op()
        self._refresh_log()
        self._check_chain()

    def _use_last_op(self):
        if self.controller.last_operation_id:
            self.op_id_var.set(self.controller.last_operation_id)
        else:
            messagebox.showinfo("No operation yet", "Perform an operation first or enter an operation ID.")

    def _get_score(self):
        op_id = self.op_id_var.get().strip()
        if not op_id:
            self._use_last_op()
            op_id = self.op_id_var.get().strip()
        if not op_id:
            messagebox.showwarning("Missing ID", "Please enter or select an Operation ID.")
            return

        try:
            tl = get_trust_layer()
            result = tl.get_assurance_score(op_id)
            color = GRADE_COLORS.get(result.get("grade"), COLORS["text"])
            self.score_label.config(text=f"{result.get('score')} / {result.get('max_score')}", fg=color)
            self.verdict_label.config(text=f"Grade {result.get('grade')}  —  {result.get('verdict')}", fg=color)
            b = result.get("breakdown", {})
            self.breakdown_label.config(
                text=(f"Sanitization Method Score:    {b.get('sanitization_method_score', 0):>2} / 30\n"
                      f"Cryptographic Verification:   {b.get('verification_passed', 0):>2} / 25\n"
                      f"Post-Wipe Recovery Validation: {b.get('recovery_validation_passed', 0):>2} / 25\n"
                      f"Audit Hash Chain Integrity:   {b.get('audit_chain_intact', 0):>2} / 20"),
                font=FONTS["mono"],
            )
        except ValueError as e:
            self.score_label.config(text="—", fg=COLORS["text_muted"])
            self.verdict_label.config(text=f"Operation not found: {op_id}", fg=COLORS["danger"])
            self.breakdown_label.config(text="")
            messagebox.showerror("Operation Not Found", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to compute assurance score: {e}")

    def _refresh_log(self):
        try:
            for row in self.tree.get_children():
                self.tree.delete(row)
            tl = get_trust_layer()
            for entry in tl.get_audit_log(limit=100):
                self.tree.insert("", "end", values=(entry["sequence"], entry["event_type"],
                                                     entry["summary"], entry["timestamp"]))
        except Exception as e:
            messagebox.showerror("Log Error", f"Failed to load audit log: {e}")

    def _check_chain(self):
        try:
            tl = get_trust_layer()
            result = tl.verify_chain_integrity()
            if result.get("chain_intact"):
                self.chain_label.config(text=f"\u2713 Chain intact ({result.get('total_entries', 0)} entries)",
                                         foreground=COLORS["success"])
            else:
                self.chain_label.config(
                    text=f"\u2717 CHAIN BROKEN at seq {result.get('first_broken_at_sequence')}",
                    foreground=COLORS["danger"],
                )
        except Exception as e:
            self.chain_label.config(text="Integrity check failed", foreground=COLORS["danger"])
