import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import role4_file_ops
from gui.theme import COLORS, FONTS
from gui.async_runner import AsyncRunner


class FileEraserPage(ttk.Frame):
    """
    Role 4: Secure File and Folder Erasure.
    Enforces RBAC (ERASE_FILE) and logs audit events to Role 6 TrustLayer.
    """

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.paths = []
        self.is_busy = False
        self.runner = AsyncRunner(self)

        btn_row = ttk.Frame(self)
        btn_row.pack(anchor="w", pady=(0, 12))
        ttk.Button(btn_row, text="+ Add File(s)", command=self._add_files).pack(side="left")
        ttk.Button(btn_row, text="+ Add Folder", command=self._add_folder).pack(side="left", padx=(8, 0))
        ttk.Button(btn_row, text="Clear List", command=self._clear).pack(side="left", padx=(8, 0))

        list_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        list_card.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(list_card, height=8, relief="flat", bd=0, font=FONTS["label"],
                                   selectbackground=COLORS["accent"], highlightthickness=0)
        self.listbox.pack(fill="both", expand=True, padx=1, pady=1)

        form = ttk.LabelFrame(self, text="Erase Selected Items", style="Card.TLabelframe", padding=16)
        form.pack(fill="x", pady=16)

        ttk.Label(form, text="Method:", background=COLORS["card"]).grid(row=0, column=0, sticky="w")
        self.method_var = tk.StringVar(value=role4_file_ops.FILE_ERASE_METHODS[0])
        ttk.Combobox(
            form, textvariable=self.method_var,
            values=role4_file_ops.FILE_ERASE_METHODS, state="readonly", width=28,
        ).grid(row=0, column=1, sticky="w", padx=(10, 0))

        self.erase_btn = ttk.Button(form, text="Erase Now", style="Danger.TButton", command=self._erase)
        self.erase_btn.grid(row=0, column=2, padx=(20, 0))

        ttk.Label(self, text="Activity Log", style="Muted.TLabel", font=FONTS["small"]).pack(anchor="w")
        log_card = ttk.Frame(self, style="Card.TFrame", padding=1)
        log_card.pack(fill="both", expand=True, pady=(4, 0))
        self.result_text = tk.Text(log_card, height=6, wrap="word", relief="flat", bd=0,
                                    font=FONTS["mono"], padx=10, pady=8)
        self.result_text.pack(fill="both", expand=True)
        self.result_text.configure(state="disabled")

    def on_show(self):
        pass

    def _add_files(self):
        selected = filedialog.askopenfilenames(title="Select file(s) to erase")
        for p in selected:
            if p not in self.paths:
                self.paths.append(p)
                self.listbox.insert("end", p)

    def _add_folder(self):
        selected = filedialog.askdirectory(title="Select a folder to erase")
        if selected and selected not in self.paths:
            self.paths.append(selected)
            self.listbox.insert("end", selected)

    def _clear(self):
        self.paths = []
        self.listbox.delete(0, "end")

    def _erase(self):
        if self.is_busy:
            messagebox.showwarning("Busy", "An erasure is already in progress.")
            return

        if not self.paths:
            messagebox.showwarning("Nothing selected", "Add at least one file or folder first.")
            return

        method = self.method_var.get()
        confirmed = messagebox.askyesno(
            "Confirm Erase",
            f"This will PERMANENTLY erase and destroy {len(self.paths)} item(s) using {method}.\n\n"
            "This operation cannot be reversed. Proceed?",
        )
        if not confirmed:
            self._log("Erasure cancelled by user.")
            return

        self.is_busy = True
        self.erase_btn.configure(state="disabled")
        self._log(f"Starting secure erasure of {len(self.paths)} item(s) using {method}...")

        user_id = self.controller.session.get("username") or self.controller.session.get("user_id", "unknown")
        paths_to_erase = list(self.paths)

        self.runner.run(
            task_fn=lambda: role4_file_ops.erase_files(paths_to_erase, method, user_id),
            on_complete=self._on_erase_complete,
            on_error=self._on_erase_error,
        )

    def _on_erase_complete(self, result):
        self.is_busy = False
        self.erase_btn.configure(state="normal")

        if result.get("authorized") is False:
            messagebox.showerror("Access Denied", result.get("reason", "Unauthorized operation."))
            self._log(f"Erase blocked: {result.get('reason')}")
            return

        op_id = result.get("operation_id")
        if op_id:
            self.controller.last_operation_id = op_id

        self._log(
            f"FILE ERASURE COMPLETED:\n"
            f"  - Method:       {result.get('operation')}\n"
            f"  - Succeeded:    {result.get('files_succeeded')}/{result.get('files_total')}\n"
            f"  - Operation ID: {op_id}\n"
        )
        messagebox.showinfo("Erasure Complete", f"Successfully erased {result.get('files_succeeded')} item(s).")
        self._clear()

    def _on_erase_error(self, err_msg):
        self.is_busy = False
        self.erase_btn.configure(state="normal")
        self._log(f"Erasure error: {err_msg}")
        messagebox.showerror("Erasure Error", f"Failed to complete erasure:\n{err_msg}")

    def _log(self, message):
        self.result_text.configure(state="normal")
        self.result_text.insert("end", message + "\n")
        self.result_text.see("end")
        self.result_text.configure(state="disabled")
