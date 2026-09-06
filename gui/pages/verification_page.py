import tkinter as tk
from tkinter import ttk, messagebox

import role4_file_ops
from gui.theme import COLORS, FONTS
from gui.async_runner import AsyncRunner


class VerificationPage(ttk.Frame):
    """
    Role 4: Cryptographic Verification.
    Verifies sanitization status by checking SHA-256 pre/post hashes and content alteration.
    Logs audit events to Role 6 TrustLayer.
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

        ttk.Label(form, text="Operation ID (for correlation):", background=COLORS["card"]).grid(
            row=0, column=0, sticky="w", pady=4
        )
        self.op_id_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.op_id_var, width=25).grid(row=0, column=1, sticky="w", padx=(10, 0))

        ttk.Label(form, text="Target (device path or file path):", background=COLORS["card"]).grid(
            row=1, column=0, sticky="w", pady=4
        )
        self.target_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.target_var, width=50).grid(row=1, column=1, sticky="w", padx=(10, 0))

        ttk.Label(form, text="Target type:", background=COLORS["card"]).grid(row=2, column=0, sticky="w", pady=4)
        self.type_var = tk.StringVar(value="DEVICE")
        ttk.Combobox(form, textvariable=self.type_var, values=["DEVICE", "FILE"],
                     state="readonly", width=15).grid(row=2, column=1, sticky="w", padx=(10, 0))

        ttk.Label(form, text="Pre-operation SHA-256 hash:", background=COLORS["card"]).grid(
            row=3, column=0, sticky="w", pady=4
        )
        self.pre_hash_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.pre_hash_var, width=50).grid(row=3, column=1, sticky="w", padx=(10, 0))

        btn_row = ttk.Frame(form_card, style="Card.TFrame")
        btn_row.pack(anchor="w", pady=(16, 0))
        self.verify_btn = ttk.Button(btn_row, text="Run Verification", style="Accent.TButton", command=self._verify)
        self.verify_btn.pack(side="left")
        ttk.Button(btn_row, text="Use last device/operation", command=self._use_last).pack(side="left", padx=(8, 0))

        self.verdict_label = ttk.Label(self, text="", font=FONTS["heading"])
        self.verdict_label.pack(anchor="w", pady=(16, 8))

        details_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        details_card.pack(fill="both", expand=True)
        self.details_text = tk.Text(details_card, height=8, wrap="word", relief="flat", bd=0,
                                     font=FONTS["mono"], padx=10, pady=8)
        self.details_text.pack(fill="both", expand=True)
        self.details_text.configure(state="disabled")

    def on_show(self):
        if not self.op_id_var.get() and self.controller.last_operation_id:
            self._use_last()

    def _use_last(self):
        if self.controller.last_operation_id:
            self.op_id_var.set(self.controller.last_operation_id)
        if getattr(self.controller, "last_device_path", None):
            self.target_var.set(self.controller.last_device_path)
            self.type_var.set("DEVICE")

    def _verify(self):
        if self.is_busy:
            messagebox.showwarning("Busy", "Verification is already in progress.")
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Missing target", "Enter a device path or file path to verify.")
            return

        self.is_busy = True
        self.verify_btn.configure(state="disabled")
        self.verdict_label.config(text="Running cryptographic verification...", foreground=COLORS["accent"])

        user_id = self.controller.session.get("username") or self.controller.session.get("user_id", "unknown")
        target_type = self.type_var.get()
        pre_hash = self.pre_hash_var.get().strip()
        op_id = self.op_id_var.get().strip() or self.controller.last_operation_id

        self.runner.run(
            task_fn=lambda: role4_file_ops.verify_hash(
                target, target_type, pre_hash, user_id,
                operation_id=op_id,
            ),
            on_complete=self._on_verify_complete,
            on_error=self._on_verify_error,
        )

    def _on_verify_complete(self, result):
        self.is_busy = False
        self.verify_btn.configure(state="normal")

        if result.get("authorized") is False:
            messagebox.showerror("Access denied", result.get("reason", "Unauthorized operation."))
            self.verdict_label.config(text="Access Denied", foreground=COLORS["danger"])
            return

        verdict = result.get("verdict", "UNKNOWN")
        color = COLORS["success"] if verdict == "PASS" else COLORS["danger"]
        self.verdict_label.config(text=f"Verification Verdict: {verdict}", foreground=color)

        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("end", f"Operation ID: {result.get('operation_id', 'N/A')}\n")
        self.details_text.insert("end", f"Pre-op hash:  {result.get('pre_operation_hash', 'N/A')}\n")
        self.details_text.insert("end", f"Post-op hash: {result.get('post_operation_hash', 'N/A')}\n")
        self.details_text.insert("end", f"Hashes match: {result.get('hashes_match', False)}\n")
        self.details_text.insert("end", f"Notes:        {result.get('notes', '')}\n")
        self.details_text.configure(state="disabled")

        messagebox.showinfo("Verification Complete", f"Verification Verdict: {verdict}\nRecorded in audit chain.")

    def _on_verify_error(self, err_msg):
        self.is_busy = False
        self.verify_btn.configure(state="normal")
        self.verdict_label.config(text="Verification Error", foreground=COLORS["danger"])
        messagebox.showerror("Verification Error", f"Failed to run verification:\n{err_msg}")
