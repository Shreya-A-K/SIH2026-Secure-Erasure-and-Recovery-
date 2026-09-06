import tkinter as tk
from tkinter import ttk

from backend.auth.login import authenticate
from backend.auth.session import login_user
from gui.theme import COLORS, FONTS


class LoginPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(style="TFrame")

        # Card centered on the page
        card = ttk.Frame(self, style="Card.TFrame", padding=44)
        card.place(relx=0.5, rely=0.5, anchor="center")

        badge = tk.Frame(card, bg=COLORS["accent"], width=52, height=52)
        badge.pack(pady=(0, 18))
        badge.pack_propagate(False)
        tk.Label(badge, text="\U0001F512", bg=COLORS["accent"], fg="white", font=(FONTS["title"][0], 20)).pack(
            expand=True
        )

        ttk.Label(card, text="Secure Data Erasure &", style="Title.TLabel", background=COLORS["card"]).pack()
        ttk.Label(card, text="Forensic Recovery Tool", style="Title.TLabel", background=COLORS["card"]).pack(
            pady=(0, 6)
        )
        ttk.Label(
            card, text="SIH 26149  \u2022  NTRO  \u2022  Blockchain & Cybersecurity",
            style="Muted.TLabel", background=COLORS["card"],
        ).pack(pady=(0, 28))

        form = ttk.Frame(card, style="Card.TFrame")
        form.pack(fill="x")

        ttk.Label(form, text="USERNAME", style="Card.TLabel", font=FONTS["small"]).grid(
            row=0, column=0, sticky="w", pady=(0, 4)
        )
        self.username_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.username_var, width=32, font=FONTS["label"]).grid(
            row=1, column=0, sticky="ew", pady=(0, 16), ipady=4
        )

        ttk.Label(form, text="PASSWORD", style="Card.TLabel", font=FONTS["small"]).grid(
            row=2, column=0, sticky="w", pady=(0, 4)
        )
        self.password_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.password_var, show="\u2022", width=32, font=FONTS["label"]).grid(
            row=3, column=0, sticky="ew", pady=(0, 6), ipady=4
        )

        form.grid_columnconfigure(0, weight=1)

        self.error_label = ttk.Label(card, text="", foreground=COLORS["danger"], background=COLORS["card"])
        self.error_label.pack(anchor="w", pady=(2, 0))

        ttk.Button(card, text="Login", style="Accent.TButton", command=self._attempt_login).pack(
            fill="x", pady=(18, 0)
        )

        ttk.Separator(card).pack(fill="x", pady=20)

        demo = ttk.Frame(card, style="Card.TFrame")
        demo.pack(fill="x")
        ttk.Label(demo, text="DEMO ACCOUNTS", style="Card.TLabel", font=FONTS["small"]).pack(anchor="w")
        for label in ("admin / Admin@123456  \u2014  full access",
                      "operator1 / Operator@123  \u2014  device, sanitize & file ops",
                      "investigator1 / Investigator@123  \u2014  recovery & reports"):
            ttk.Label(demo, text=label, style="Muted.TLabel", background=COLORS["card"],
                      font=FONTS["small"]).pack(anchor="w", pady=(4, 0))

        self.bind_all("<Return>", lambda e: self._attempt_login())

    def on_show(self):
        self.username_var.set("")
        self.password_var.set("")
        self.error_label.config(text="")

    def _attempt_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        if not username or not password:
            self.error_label.config(text="Enter both username and password.")
            return

        user = authenticate(username, password)
        if user:
            login_user(user)  # Person 2's session system - creates the session
            self.controller.login(user["id"], user["username"], user["role"])
        else:
            self.error_label.config(text="Invalid username or password.")
