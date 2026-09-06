import tkinter as tk
from tkinter import ttk

from backend import role6_trust
from gui.theme import COLORS, FONTS

GRADE_COLORS = {"A+": COLORS["success"], "A": COLORS["success"], "B": COLORS["warning"],
                "C": COLORS["warning"], "F": COLORS["danger"]}


class AssurancePage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        top = ttk.Frame(self, style="Card.TFrame", padding=20)
        top.pack(fill="x")
        ttk.Label(top, text="Operation ID:", background=COLORS["card"]).grid(row=0, column=0, sticky="w")
        self.op_id_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.op_id_var, width=18).grid(row=0, column=1, padx=(10, 0))
        ttk.Button(top, text="Use last", command=self._use_last_op).grid(row=0, column=2, padx=(10, 0))
        ttk.Button(top, text="Get Score", style="Accent.TButton", command=self._get_score).grid(
            row=0, column=3, padx=(10, 0)
        )

        score_card = ttk.Frame(self, style="Card.TFrame", padding=20)
        score_card.pack(fill="x", pady=(16, 0))
        self.score_label = tk.Label(score_card, text="\u2014", font=FONTS["score"], bg=COLORS["card"])
        self.score_label.pack(anchor="w")
        self.verdict_label = tk.Label(score_card, text="Run a check to see the assurance score",
                                       font=FONTS["label_bold"], bg=COLORS["card"], fg=COLORS["text_muted"])
        self.verdict_label.pack(anchor="w", pady=(2, 10))
        self.breakdown_label = ttk.Label(score_card, text="", justify="left", background=COLORS["card"])
        self.breakdown_label.pack(anchor="w")

        audit_bar = ttk.Frame(self)
        audit_bar.pack(fill="x", pady=(20, 8))
        ttk.Label(audit_bar, text="Audit Log", style="Heading.TLabel").pack(side="left")
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
        for col, label, width in zip(columns, ("#", "Event", "Summary", "Timestamp"), (40, 160, 340, 160)):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width)
        self.tree.pack(fill="both", expand=True, padx=1, pady=1)

    def on_show(self):
        self._refresh_log()

    def _use_last_op(self):
        if self.controller.last_operation_id:
            self.op_id_var.set(self.controller.last_operation_id)

    def _get_score(self):
        op_id = self.op_id_var.get()
        if not op_id:
            self._use_last_op()
            op_id = self.op_id_var.get()
        if not op_id:
            return

        result = role6_trust.get_assurance_score(op_id)
        color = GRADE_COLORS.get(result["grade"], COLORS["text"])
        self.score_label.config(text=f"{result['score']} / {result['max_score']}", fg=color)
        self.verdict_label.config(text=f"Grade {result['grade']}  \u2014  {result['verdict']}", fg=color)
        b = result["breakdown"]
        self.breakdown_label.config(
            text=(f"Sanitization method   {b['sanitization_method_score']}/30\n"
                  f"Verification          {b['verification_passed']}/25\n"
                  f"Recovery validation   {b['recovery_validation_passed']}/25\n"
                  f"Audit chain intact    {b['audit_chain_intact']}/7"),
            font=FONTS["mono"],
        )

    def _refresh_log(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for entry in role6_trust.get_audit_log(limit=100):
            self.tree.insert("", "end", values=(entry["sequence"], entry["event_type"],
                                                 entry["summary"], entry["timestamp"]))

    def _check_chain(self):
        result = role6_trust.verify_chain_integrity()
        if result["chain_intact"]:
            self.chain_label.config(text=f"\u2713 Chain intact ({result['total_entries']} entries)",
                                     foreground=COLORS["success"])
        else:
            self.chain_label.config(
                text=f"\u2717 CHAIN BROKEN at sequence {result['first_broken_at_sequence']}",
                foreground=COLORS["danger"],
            )
