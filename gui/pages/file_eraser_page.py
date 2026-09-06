import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from backend import role4_file_ops
from gui.theme import COLORS, FONTS


class FileEraserPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.paths = []

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
            values=role4_file_ops.FILE_ERASE_METHODS, state="readonly", width=20,
        ).grid(row=0, column=1, sticky="w", padx=(10, 0))

        ttk.Button(form, text="Erase Now", style="Danger.TButton", command=self._erase).grid(
            row=0, column=2, padx=(20, 0)
        )

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
        if not self.paths:
            messagebox.showwarning("Nothing selected", "Add at least one file or folder first.")
            return

        confirmed = messagebox.askyesno(
            "Confirm erase",
            f"This will PERMANENTLY erase {len(self.paths)} item(s). Continue?",
        )
        if not confirmed:
            return

        user_id = self.controller.session.get("user_id", "unknown")
        result = role4_file_ops.erase_files(self.paths, self.method_var.get(), user_id)

        if result.get("authorized") is False:
            messagebox.showerror("Access denied", result.get("reason", "You don't have permission to do this."))
            return

        self._log(
            f"{result['operation']} erase complete - "
            f"{result['files_succeeded']}/{result['files_total']} succeeded."
        )
        self._clear()

    def _log(self, message):
        self.result_text.configure(state="normal")
        self.result_text.insert("end", message + "\n")
        self.result_text.see("end")
        self.result_text.configure(state="disabled")
