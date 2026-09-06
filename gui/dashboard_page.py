import tkinter as tk
from tkinter import ttk

from auth.rbac import has_permission
from gui.pages.device_page import DevicePage
from gui.pages.file_eraser_page import FileEraserPage
from gui.pages.verification_page import VerificationPage
from gui.pages.recovery_page import RecoveryPage
from gui.pages.assurance_page import AssurancePage
from gui.pages.reports_page import ReportsPage
from gui.theme import COLORS, FONTS

# (section_key, icon, sidebar_label, PageClass, required_permission)
# required_permission decides whether the TAB ITSELF shows at all.
# DETECT_USB is shared by ADMIN/OPERATOR/INVESTIGATOR, so all three see
# the Device tab - but the Sanitize form and Post-Wipe Validation panel
# inside DevicePage are further gated on SANITIZE_USB / VALIDATE_SANITIZATION
# (see device_page.py), so an Investigator sees devices but can't wipe them.
SECTIONS = [
    ("device", "\U0001F4BE", "Device & Sanitization", DevicePage, "DETECT_USB"),
    ("file_eraser", "\U0001F5D1", "File / Folder Eraser", FileEraserPage, "ERASE_FILE"),
    ("verification", "\u2713", "Verification", VerificationPage, "ERASE_FILE"),
    ("recovery", "\U0001F50D", "Recovery / Carving", RecoveryPage, "VIEW_RECOVERY"),
    ("assurance", "\U0001F4CA", "Assurance & Audit", AssurancePage, "VIEW_AUDIT"),
    ("reports", "\U0001F4C4", "Reports / Certificates", ReportsPage, "GENERATE_REPORT"),
]

ROLE_COLORS = {
    "ADMIN": COLORS["accent"],
    "OPERATOR": COLORS["success"],
    "INVESTIGATOR": COLORS["warning"],
}


class DashboardPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.active_key = None

        # ---- Sidebar (plain tk.Frame so we get the exact navy bg) -----
        sidebar = tk.Frame(self, width=268, bg=COLORS["sidebar"])
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        header = tk.Frame(sidebar, bg=COLORS["sidebar"])
        header.pack(fill="x", padx=20, pady=(24, 18))
        tk.Label(header, text="SIH 26149", bg=COLORS["sidebar"], fg=COLORS["sidebar_text_active"],
                 font=FONTS["label_bold"]).pack(anchor="w")
        tk.Label(header, text="Erasure & Recovery Tool", bg=COLORS["sidebar"], fg=COLORS["sidebar_muted"],
                 font=FONTS["small"]).pack(anchor="w", pady=(2, 0))

        user_card = tk.Frame(sidebar, bg=COLORS["sidebar_hover"])
        user_card.pack(fill="x", padx=16, pady=(0, 16))
        self.user_label = tk.Label(user_card, text="", bg=COLORS["sidebar_hover"],
                                    fg=COLORS["sidebar_text_active"], font=FONTS["label_bold"], anchor="w")
        self.user_label.pack(fill="x", padx=12, pady=(10, 0))
        self.role_label = tk.Label(user_card, text="", bg=COLORS["sidebar_hover"],
                                    fg=COLORS["accent"], font=FONTS["small"], anchor="w")
        self.role_label.pack(fill="x", padx=12, pady=(0, 10))

        nav_container = tk.Frame(sidebar, bg=COLORS["sidebar"])
        nav_container.pack(fill="x", padx=12)

        self.nav_buttons = {}
        for key, icon, label, _cls, _perm in SECTIONS:
            btn = ttk.Button(
                nav_container, text=f"  {icon}   {label}", style="Nav.TButton",
                command=lambda k=key: self._show_section(k),
            )
            # Not packed yet - on_show() packs only the sections this
            # role actually has permission for. A disabled-but-visible
            # button still reads as "this role can see this feature",
            # so unauthorized sections are removed from layout entirely,
            # not just grayed out.
            self.nav_buttons[key] = btn

        spacer = tk.Frame(sidebar, bg=COLORS["sidebar"])
        spacer.pack(fill="both", expand=True)

        bottom = tk.Frame(sidebar, bg=COLORS["sidebar"])
        bottom.pack(fill="x", padx=12, pady=16)
        ttk.Button(bottom, text="Logout", style="Logout.TButton", command=self.controller.logout).pack(fill="x")

        # ---- Content area ---------------------------------------------
        content_outer = tk.Frame(self, bg=COLORS["bg"])
        content_outer.pack(side="left", fill="both", expand=True)

        topbar = tk.Frame(content_outer, bg=COLORS["bg"])
        topbar.pack(fill="x", padx=28, pady=(22, 0))
        self.section_title = ttk.Label(topbar, text="", style="Heading.TLabel")
        self.section_title.pack(anchor="w")

        content = ttk.Frame(content_outer, padding=(28, 16, 28, 24))
        content.pack(fill="both", expand=True)
        content.grid_rowconfigure(0, weight=1)
        content.grid_columnconfigure(0, weight=1)

        self.section_frames = {}
        for key, _icon, _label, cls, _perm in SECTIONS:
            frame = cls(parent=content, controller=controller)
            self.section_frames[key] = frame
            frame.grid(row=0, column=0, sticky="nsew")

    def on_show(self):
        session = self.controller.session
        self.user_label.config(text=session.get("username") or "")
        role = session.get("role")
        self.role_label.config(text=role or "", fg=ROLE_COLORS.get(role, COLORS["accent"]))

        first_allowed = None
        for key, _icon, _label, _cls, permission in SECTIONS:
            allowed = has_permission(permission)
            btn = self.nav_buttons[key]
            if allowed:
                btn.pack(fill="x", pady=2)
                if first_allowed is None:
                    first_allowed = key
            else:
                btn.pack_forget()

        if first_allowed:
            self._show_section(first_allowed)

    def _show_section(self, key):
        for k, _icon, label, _cls, _perm in SECTIONS:
            if k in self.nav_buttons:
                self.nav_buttons[k].configure(style="NavActive.TButton" if k == key else "Nav.TButton")
            if k == key:
                self.section_title.config(text=label)

        frame = self.section_frames[key]
        if hasattr(frame, "on_show"):
            frame.on_show()
        frame.tkraise()
        self.active_key = key
