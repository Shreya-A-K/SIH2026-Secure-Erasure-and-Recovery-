"""
Central visual theme for the app. One place to tune colors/fonts so
every page looks consistent. Import COLORS/FONTS for direct use in
custom widgets (e.g. verdict labels), and call apply_theme(root) once
at startup to configure all the ttk styles.
"""

COLORS = {
    "bg": "#F4F6FA",            # main content background
    "sidebar": "#101A2E",        # dark navy sidebar
    "sidebar_hover": "#1B2A4A",
    "sidebar_active": "#2563EB",  # accent blue for the selected nav item
    "sidebar_text": "#CBD5E1",
    "sidebar_text_active": "#FFFFFF",
    "sidebar_muted": "#64748B",
    "accent": "#2563EB",
    "accent_dark": "#1D4ED8",
    "card": "#FFFFFF",
    "border": "#E2E8F0",
    "text": "#0F172A",
    "text_muted": "#64748B",
    "success": "#16A34A",
    "success_bg": "#DCFCE7",
    "danger": "#DC2626",
    "danger_bg": "#FEE2E2",
    "warning": "#D97706",
    "warning_bg": "#FEF3C7",
}

FONT_FAMILY = "Segoe UI"
FONTS = {
    "title": (FONT_FAMILY, 20, "bold"),
    "subtitle": (FONT_FAMILY, 10),
    "heading": (FONT_FAMILY, 15, "bold"),
    "label": (FONT_FAMILY, 10),
    "label_bold": (FONT_FAMILY, 10, "bold"),
    "small": (FONT_FAMILY, 8),
    "mono": ("Consolas", 10),
    "score": (FONT_FAMILY, 24, "bold"),
    "nav": (FONT_FAMILY, 10),
}


def apply_theme(root):
    """Configure ttk styles. Call once, right after creating the Tk root."""
    from tkinter import ttk

    root.configure(bg=COLORS["bg"])

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    # --- generic ---------------------------------------------------
    style.configure(".", font=FONTS["label"], background=COLORS["bg"], foreground=COLORS["text"])
    style.configure("TFrame", background=COLORS["bg"])
    style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=FONTS["label"])
    style.configure("TSeparator", background=COLORS["border"])

    # Card-style frame (used for form panels / labelframes)
    style.configure("Card.TFrame", background=COLORS["card"])
    style.configure(
        "Card.TLabelframe", background=COLORS["card"], bordercolor=COLORS["border"],
        relief="solid", borderwidth=1,
    )
    style.configure(
        "Card.TLabelframe.Label", background=COLORS["card"], foreground=COLORS["text"],
        font=FONTS["label_bold"],
    )
    style.configure("TLabelframe", background=COLORS["bg"], bordercolor=COLORS["border"])
    style.configure("TLabelframe.Label", background=COLORS["bg"], font=FONTS["label_bold"])

    style.configure("Heading.TLabel", font=FONTS["heading"], background=COLORS["bg"])
    style.configure("Title.TLabel", font=FONTS["title"], background=COLORS["bg"])
    style.configure("Muted.TLabel", foreground=COLORS["text_muted"], background=COLORS["bg"])
    style.configure("Card.TLabel", background=COLORS["card"], font=FONTS["label"])

    # --- buttons -----------------------------------------------------
    style.configure(
        "TButton", font=FONTS["label"], padding=(12, 8), relief="flat",
        background="#E2E8F0", foreground=COLORS["text"],
    )
    style.map("TButton", background=[("active", "#D6DEE8"), ("disabled", "#EEF1F5")])

    style.configure(
        "Accent.TButton", font=FONTS["label_bold"], padding=(14, 9),
        background=COLORS["accent"], foreground="white", relief="flat",
    )
    style.map("Accent.TButton", background=[("active", COLORS["accent_dark"]), ("disabled", "#93B4F5")])

    style.configure(
        "Danger.TButton", font=FONTS["label_bold"], padding=(14, 9),
        background=COLORS["danger"], foreground="white", relief="flat",
    )
    style.map("Danger.TButton", background=[("active", "#B91C1C")])

    # --- sidebar nav buttons ------------------------------------------
    style.configure(
        "Nav.TButton", font=FONTS["nav"], padding=(14, 10), relief="flat",
        background=COLORS["sidebar"], foreground=COLORS["sidebar_text"],
        borderwidth=0, anchor="w",
    )
    style.map(
        "Nav.TButton",
        background=[("active", COLORS["sidebar_hover"]), ("disabled", COLORS["sidebar"])],
        foreground=[("disabled", COLORS["sidebar_muted"])],
    )
    style.configure(
        "NavActive.TButton", font=FONTS["label_bold"], padding=(14, 10), relief="flat",
        background=COLORS["sidebar_active"], foreground=COLORS["sidebar_text_active"],
        borderwidth=0, anchor="w",
    )
    style.map("NavActive.TButton", background=[("active", COLORS["accent_dark"])])

    style.configure(
        "Logout.TButton", font=FONTS["label"], padding=(14, 9), relief="flat",
        background=COLORS["sidebar_hover"], foreground=COLORS["sidebar_text_active"],
    )
    style.map("Logout.TButton", background=[("active", "#2A3B5F")])

    # --- entries / combobox --------------------------------------------
    style.configure("TEntry", padding=6, fieldbackground="white", bordercolor=COLORS["border"])
    style.configure("TCombobox", padding=6, fieldbackground="white")

    # --- Treeview --------------------------------------------------------
    style.configure(
        "Treeview", background="white", fieldbackground="white", foreground=COLORS["text"],
        rowheight=28, font=FONTS["label"], borderwidth=0,
    )
    style.configure(
        "Treeview.Heading", font=FONTS["label_bold"], background="#EEF2F7",
        foreground=COLORS["text"], relief="flat", padding=(6, 6),
    )
    style.map("Treeview", background=[("selected", COLORS["accent"])], foreground=[("selected", "white")])
    style.map("Treeview.Heading", background=[("active", "#E2E8F0")])
