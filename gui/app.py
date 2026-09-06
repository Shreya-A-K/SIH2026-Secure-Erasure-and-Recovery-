"""
Main application shell.

Uses the standard Tkinter "multi-page" pattern: one Tk root, a
container frame, and several Frame subclasses stacked on top of each
other. show_frame(name) raises the requested one.
"""

import tkinter as tk
from tkinter import ttk

from gui.login_page import LoginPage
from gui.dashboard_page import DashboardPage
from gui.theme import apply_theme, COLORS


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Data Erasure & Forensic Recovery Tool - SIH 26149")
        self.geometry("1180x720")
        self.minsize(1000, 640)

        # Session state shared across every page
        self.session = {"user_id": None, "username": None, "role": None}
        # Last operation_id, so pages can hand off context to each other
        # (e.g. sanitize a device -> jump to recovery validation for the
        # same operation_id -> jump to reports for the same operation_id)
        self.last_operation_id = None
        self.last_device_path = None

        apply_theme(self)
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for PageClass in (LoginPage, DashboardPage):
            page = PageClass(parent=container, controller=self)
            self.frames[PageClass.__name__] = page
            page.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginPage")

    def show_frame(self, name):
        frame = self.frames[name]
        if hasattr(frame, "on_show"):
            frame.on_show()
        frame.tkraise()

    def login(self, user_id, username, role):
        self.session = {"user_id": user_id, "username": username, "role": role}
        self.show_frame("DashboardPage")

    def logout(self):
        from backend.auth.session import logout as auth_logout
        auth_logout()  # clears Person 2's real session, not just GUI display state
        self.session = {"user_id": None, "username": None, "role": None}
        self.last_operation_id = None
        self.last_device_path = None
        self.show_frame("LoginPage")


def run():
    app = App()
    app.mainloop()
