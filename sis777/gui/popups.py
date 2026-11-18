"""Decision pop-ups (P-00 to P-12). All pop-ups are modal; the default (Enter) is always the safe choice."""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import messagebox, ttk

ORANGE, BLUE, NAVY = "#E67C00", "#1967D2", "#1F3864"
UI_FONT = "Malgun Gothic"
FONT = (UI_FONT, 10)
FONT_B = (UI_FONT, 10, "bold")


class Dialog(tk.Toplevel):
    """Common modal window: orange title bar + body + button row."""

    def __init__(self, parent, title: str, width: int = 640, step: int | None = None):
        super().__init__(parent)
        self.answer = None
        self.withdraw()
        self.title("Decision required" + (f" — {step}. {title}" if step else f" — {title}"))
        if parent.winfo_viewable():
            self.transient(parent)
        self.resizable(True, True)
        head = tk.Label(self, text=self.title(), bg=ORANGE, fg="white", font=(UI_FONT, 11, "bold"), anchor="w", padx=12, pady=6)
        head.pack(fill="x")
        self.body = tk.Frame(self, padx=14, pady=10)
        self.body.pack(fill="both", expand=True)
        self.btns = tk.Frame(self, padx=14, pady=10)
        self.btns.pack(fill="x")
        self.minsize(width, 120)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):  # closing the window = the safe choice
        self.destroy()

    def button(self, text: str, value, primary: bool = False, default: bool = False):
        b = tk.Button(self.btns, text=text, font=FONT_B, width=14, relief="groove",
                      bg=BLUE if primary else "#e6e6e6", fg="white" if primary else "#222",
                      command=lambda: self.done(value))
        b.pack(side="right", padx=4)
        if default:
            self.bind("<Return>", lambda e: self.done(value))
            b.focus_set()
        return b

    def done(self, value):
        self.answer = value() if callable(value) else value
        self.destroy()

    def show(self):
        self.update_idletasks()
        p = self.master
        if p.winfo_viewable():
            x = p.winfo_rootx() + max(0, (p.winfo_width() - self.winfo_reqwidth()) // 2)
            y = p.winfo_rooty() + max(0, (p.winfo_height() - self.winfo_reqheight()) // 3)
        else:
            x = (self.winfo_screenwidth() - self.winfo_reqwidth()) // 2
            y = (self.winfo_screenheight() - self.winfo_reqheight()) // 3
        self.attributes("-topmost", True)
        self.geometry(f"+{x}+{y}")
        self.deiconify()
        self.grab_set()
        self.wait_window()
        return self.answer


def label(parent, text, **kw):
    lb = tk.Label(parent, text=text, font=kw.pop("font", FONT), justify="left", anchor="w", wraplength=kw.pop("wrap", 600), **kw)
    lb.pack(fill="x", pady=2)
    return lb


# ---------------------------------------------------------------- P-02 inspection info
def p02(root, pl: dict):
    d = Dialog(root, "Confirm inspection info", step=3)
    if pl["is_new"]:
        label(d.body, "New PC — a storage folder named after the system name will be created on the USB.", fg=ORANGE, font=FONT_B)
    else:
        label(d.body, f"Known PC — storage folder: {pl.get('folder', '')} (changing the system name renames the folder)", fg="#555")
    label(d.body, f"Computer: {pl['computer']}    OS: {pl['os']}")
    grid = tk.Frame(d.body)
    grid.pack(fill="x", pady=6)
    vars_ = {}
    for i, (k, t) in enumerate((("system_name", "System name *"), ("purpose", "Purpose"), ("asset_no", "Asset no."))):
        tk.Label(grid, text=t, font=FONT, width=13, anchor="w").grid(row=i, column=0, sticky="w", pady=2)
        v = tk.StringVar(value=pl.get(k, ""))
        tk.Entry(grid, textvariable=v, font=FONT, width=50).grid(row=i, column=1, sticky="we", pady=2)
        vars_[k] = v
    tk.Label(grid, text="MAC address", font=FONT, width=13, anchor="w").grid(row=3, column=0, sticky="w", pady=2)
    opts = [f"{m}  |  {n}  |  {ip}" for m, n, ip in pl["adapters"]] or [pl["mac"]]
    mac_v = tk.StringVar(value=next((o for o in opts if o.startswith(pl["mac"])), opts[0]))
    ttk.Combobox(grid, textvariable=mac_v, values=opts, state="readonly", width=60).grid(row=3, column=1, sticky="we", pady=2)
    if len(opts) > 1:
        label(d.body, "Several adapters found. Choose the MAC address to print on the checklist.", fg="#555")
    label(d.body, "* System name is required; it is used as the storage folder name on the USB.", fg="#555")
    tk.Label(grid, text="Type", font=FONT, width=13, anchor="w").grid(row=4, column=0, sticky="w", pady=2)
    type_v = tk.StringVar(value=pl["type"])
    rf = tk.Frame(grid)
    rf.grid(row=4, column=1, sticky="w")
    # values stay Korean: they are the checkbox labels of the official checklist form
    for t, en in (("신규", "New"), ("정기", "Regular"), ("수시", "Ad hoc")):
        tk.Radiobutton(rf, text=en, variable=type_v, value=t, font=FONT).pack(side="left", padx=4)

    def ok():
        return {**{k: v.get().strip() for k, v in vars_.items()}, "mac": mac_v.get().split()[0], "type": type_v.get()}
    d.button("Stop", None)
    d.button("OK", ok, primary=True, default=True)
    return d.show()


# ---------------------------------------------------------------- P-03 self-check
def p03(root, pl: dict):
    d = Dialog(root, f"Self-check ({pl['index']}/{pl['total']})", step=5)
    label(d.body, f"[{pl['code']}]", font=FONT_B)
    label(d.body, pl["text"], font=(UI_FONT, 11))
    rest = tk.BooleanVar(value=False)
    tk.Checkbutton(d.body, text="Apply the same answer to the remaining questions", variable=rest, font=FONT).pack(anchor="w", pady=6)
    mk = lambda a: (lambda: {"answer": a, "apply_rest": rest.get()})
    d.button("Later", mk("later"), default=True)
    d.button("No", mk("no"))
    d.button("Yes", mk("yes"), primary=True)
    return d.show() or {"answer": "later", "apply_rest": False}


# ---------------------------------------------------------------- P-04 confirm auto-fix
def p04(root, pl: dict, on_stop):
    rows = pl["rows"]
    d = Dialog(root, "Confirm auto-fix", width=860, step=7)
    label(d.body, "Vulnerable items will be set to the recommended values. Review the items to change (double-click to select/clear).")
    tv = ttk.Treeview(d.body, columns=("sel", "code", "desc", "chg", "warn"), show="headings", height=min(14, max(4, len(rows))))
    for c, t, w in (("sel", "Select", 50), ("code", "Code", 70), ("desc", "Item", 300), ("chg", "Current → New", 300), ("warn", "Note", 110)):
        tv.heading(c, text=t)
        tv.column(c, width=w, anchor="center" if c in ("sel", "code") else "w")
    checked = {}
    for i, r in enumerate(rows):
        on = not (r["risky"] or r["irreversible"])
        checked[str(i)] = on
        warn = "Irreversible" if r["irreversible"] else ("Confirm each" if r["risky"] else "")
        tv.insert("", "end", iid=str(i), values=("☑" if on else "☐", r["code"], r["desc"], f"{r['before']} → {r['after']}", warn))
    tv.pack(fill="both", expand=True, pady=6)

    def toggle(_e=None):
        for iid in tv.selection():
            checked[iid] = not checked[iid]
            tv.set(iid, "sel", "☑" if checked[iid] else "☐")
    tv.bind("<Double-1>", toggle)
    tv.bind("<space>", toggle)
    note = tk.Frame(d.body, bg="#FFF8E1", padx=10, pady=6)
    note.pack(fill="x")
    for t in ("• Current values are backed up to the USB first and can be reverted with [Restore] (except irreversible items).",
              "• 'Confirm each' items ask once more before they run.",
              "• Items managed by Group Policy or a security product, and items marked as exceptions, are not listed."):
        tk.Label(note, text=t, bg="#FFF8E1", fg="#5a4600", font=FONT, anchor="w").pack(fill="x")

    def stop():
        on_stop()
        return None
    d.button("Stop", stop)
    d.button("Skip", [], default=True)
    d.button("Apply selected", lambda: [(rows[int(i)]["code"], rows[int(i)]["key"]) for i, on in checked.items() if on], primary=True)
    return d.show()


# ---------------------------------------------------------------- P-05 confirm a risky item
def p05(root, pl: dict):
    d = Dialog(root, "Confirm risky item", step=7)
    label(d.body, f"[{pl['code']}] {pl['title']}", font=FONT_B)
    label(d.body, f"{pl['desc']}\nCurrent: {pl['before']}  →  New: {pl['after']}")
    if pl["irreversible"]:
        label(d.body, "This change cannot be reverted.", fg="#C62828", font=FONT_B)
    rest = tk.BooleanVar(value=False)
    tk.Checkbutton(d.body, text="Apply the same choice to the remaining risky items", variable=rest, font=FONT).pack(anchor="w", pady=6)
    d.button("Skip this item", lambda: {"answer": "skip", "apply_rest": rest.get()}, default=True)
    d.button("Apply", lambda: {"answer": "yes", "apply_rest": rest.get()}, primary=True)
    return d.show() or {"answer": "skip"}


# ---------------------------------------------------------------- P-06 fix failed
def p06(root, pl: dict):
    d = Dialog(root, "Fix failed", step=7)
    label(d.body, f"[{pl['code']}] {pl['item']}: the change failed.", font=FONT_B)
    label(d.body, pl["error"], fg="#C62828")
    box = tk.LabelFrame(d.body, text="To mark as an exception", font=FONT, padx=8, pady=6)
    box.pack(fill="x", pady=6)
    reason, measure, doc = tk.StringVar(), tk.StringVar(), tk.BooleanVar()
    for t, v in (("Reason", reason), ("Mitigation", measure)):
        f = tk.Frame(box)
        f.pack(fill="x", pady=2)
        tk.Label(f, text=t, width=10, anchor="w", font=FONT).pack(side="left")
        tk.Entry(f, textvariable=v, font=FONT).pack(side="left", fill="x", expand=True)
    tk.Checkbutton(box, text="Vendor documentation available (to submit with the checklist)", variable=doc, font=FONT).pack(anchor="w")

    def exc():
        if not reason.get().strip():
            messagebox.showwarning("Exception", "Enter a reason.", parent=d)
            return "retry_dialog"
        return {"answer": "except", "reason": reason.get().strip(), "measure": measure.get().strip(), "vendor_doc": doc.get()}
    d.button("Skip", "skip", default=True)
    d.button("Mark as exception", exc)
    d.button("Retry", "retry", primary=True)
    a = d.show()
    return p06(root, pl) if a == "retry_dialog" else (a or "skip")


def open_folder(path: str) -> None:
    """Open a folder with Windows Explorer (full path). Does nothing if the path is not a folder."""
    import subprocess
    from ..core.ps import SYSROOT
    if os.name == "nt" and os.path.isdir(path):
        subprocess.Popen([os.path.join(SYSROOT, "explorer.exe"), os.path.normpath(path)])


# ---------------------------------------------------------------- P-07 information
def info(root, pl: dict):
    messagebox.showinfo(pl.get("title", "Notice"), pl.get("message", ""), parent=root)
    return "ok"


# ---------------------------------------------------------------- P-08 restart notice
def p08(root, pl: dict):
    d = Dialog(root, "Restart required", step=8)
    if pl["reboot"]:
        label(d.body, "Items applied after a restart: " + ", ".join(pl["reboot"]))
    if pl["relogon"]:
        label(d.body, "Items fully applied after signing in again: " + ", ".join(pl["relogon"]))
    d.button("Later", "later", default=True)
    if pl["reboot"]:
        d.button("Save and restart (in 30 s)", "now", primary=True)
    return d.show() or "later"


# ---------------------------------------------------------------- P-09 finished
def p09(root, pl: dict):
    d = Dialog(root, "Inspection finished", width=700, step=9)
    c = pl["counts"]
    label(d.body, f"Score {pl['score_before']} → {pl['score_after']}", font=(UI_FONT, 14, "bold"), fg=NAVY)
    # count keys are the Korean status values used in the reports
    label(d.body, f"Good {c['양호']} · Partial {c['부분 설정']} · Vulnerable {c['취약']} · Exception {c['예외']} · "
                  f"Manual {c['수동 확인']} · N/A {c['해당 없음']} · Error {c['점검 오류']}")
    if pl["remain"]:
        label(d.body, "Remaining vulnerable/partial items: " + ", ".join(pl["remain"]), fg="#C62828")
    label(d.body, "Saved to: " + pl["folder"], font=FONT_B)
    for f in pl["files"]:
        label(d.body, "  • " + os.path.basename(f))
    d.button("Close", "ok", default=True)
    d.button("Open folder", lambda: open_folder(pl["folder"]) or "ok", primary=True)
    return d.show()


# ---------------------------------------------------------------- P-11 pick SafeUSB
def p11(root, pl: dict):
    d = Dialog(root, "Pick SafeUSB", width=820, step=4)
    label(d.body, "SafeUSB was not found under the saved names. Pick it from the installed programs or the services. "
                  "The names you pick are saved and used to identify it automatically next time.")
    q = tk.StringVar()
    sf = tk.Frame(d.body)
    sf.pack(fill="x", pady=4)
    tk.Label(sf, text="Search", font=FONT).pack(side="left")
    tk.Entry(sf, textvariable=q, font=FONT).pack(side="left", fill="x", expand=True, padx=6)
    lists = tk.Frame(d.body)
    lists.pack(fill="both", expand=True)
    boxes = {}
    for col, (k, t) in enumerate((("programs", "Installed programs (product name)"), ("services", "Services (name | display name)"))):
        f = tk.LabelFrame(lists, text=t, font=FONT)
        f.grid(row=0, column=col, sticky="nsew", padx=4)
        lb = tk.Listbox(f, font=FONT, height=14, exportselection=False, width=48)
        lb.pack(fill="both", expand=True)
        boxes[k] = lb
    lists.columnconfigure(0, weight=1)
    lists.columnconfigure(1, weight=1)

    def refill(*_):
        s = q.get().lower()
        for k, lb in boxes.items():
            lb.delete(0, "end")
            for x in pl[k]:
                if s in x.lower():
                    lb.insert("end", x)
    q.trace_add("write", refill)
    refill()

    def pick():
        p = boxes["programs"].get(boxes["programs"].curselection()[0]) if boxes["programs"].curselection() else ""
        s = boxes["services"].get(boxes["services"].curselection()[0]).split(" | ")[0] if boxes["services"].curselection() else ""
        if not p and not s:
            messagebox.showwarning("Pick SafeUSB", "Select a product or a service.", parent=d)
            return "again"
        return {"product": p, "service": s}
    d.button("Later (no verdict)", None, default=True)
    d.button("Not installed", {"not_installed": True})
    d.button("Select", pick, primary=True)
    a = d.show()
    return p11(root, pl) if a == "again" else a


# ---------------------------------------------------------------- P-12 launch password
MIN_PW = 8


def _pw_dialog(root, title: str, lines: list[str], n_entries: int, ok_text: str):
    d = Dialog(root, title, width=460, step=1)
    for ln in lines:
        label(d.body, ln, wrap=420)
    vars_ = [tk.StringVar() for _ in range(n_entries)]
    entries = []
    for v in vars_:
        e = tk.Entry(d.body, textvariable=v, show="●", font=FONT)
        e.pack(fill="x", pady=2)
        entries.append(e)
    d.button("Exit" if title.startswith("Launch") else "Cancel", None)
    d.button(ok_text, lambda: tuple(v.get() for v in vars_), primary=True, default=True)
    d.after(50, lambda: entries[0].focus_set())
    return d.show()


def p12_launch(root, wl) -> bool:
    """Launch password. On first run the user sets it; afterwards it must be entered on every launch."""
    if not wl.has_password:
        while True:
            a = _pw_dialog(root, "Launch password setup",
                           ["First run. Set the launch password (at least 8 characters, enter it twice).",
                            "The same password is used for [Register USB]. If you forget it, delete usb_whitelist.json in the program folder "
                            "and set a new one; the list of registered USB drives is deleted with it."],
                           2, "Set")
            if not a:
                return False
            if len(a[0]) < MIN_PW or a[0] != a[1]:
                messagebox.showwarning("Launch password", "The password is shorter than 8 characters or the two entries differ.", parent=root)
                continue
            wl.set_password(a[0])
            return True
    while True:
        lock = wl.locked_seconds()
        if lock:
            messagebox.showwarning("Launch password", f"Too many wrong passwords. Try again in {lock // 60 + 1} min.", parent=root)
            return False
        a = _pw_dialog(root, "Launch password", ["Enter the SIS777 launch password."], 1, "OK")
        if not a:
            return False
        if wl.verify_password(a[0]):
            return True
        left = wl.fails_left()
        if left:
            messagebox.showwarning("Launch password", f"Wrong password. ({left} more wrong attempts lock it for 10 min)", parent=root)


def change_password(root, wl) -> bool:
    """Change the launch password (after checking the current one)."""
    lock = wl.locked_seconds()
    if lock:
        messagebox.showwarning("Change password", f"Locked. Try again in {lock // 60 + 1} min.", parent=root)
        return False
    a = _pw_dialog(root, "Change password", ["Enter the current password, then the new one twice (at least 8 characters)."], 3, "Change")
    if not a:
        return False
    if not wl.verify_password(a[0]):
        messagebox.showwarning("Change password", "The current password is wrong.", parent=root)
        return False
    if len(a[1]) < MIN_PW or a[1] != a[2]:
        messagebox.showwarning("Change password", "The new password is shorter than 8 characters or the two entries differ.", parent=root)
        return False
    wl.set_password(a[1])
    messagebox.showinfo("Change password", "The launch password has been changed.", parent=root)
    return True


# ---------------------------------------------------------------- start-up (P-00, P-10)
def p00(root, reason: str, can_register: bool) -> str:
    d = Dialog(root, "Run from USB", step=1)
    label(d.body, "Run this program from a (registered) external USB drive.", font=(UI_FONT, 12, "bold"), fg="#C62828")
    label(d.body, reason)
    d.button("Exit", "exit", default=True)
    if can_register:
        d.button("Register USB", "register", primary=True)
    return d.show() or "exit"


def p10(root, wl, usb) -> bool:
    """Register this USB: set the password on first use, otherwise verify it. Returns True on success."""
    lock = wl.locked_seconds()
    if lock:
        messagebox.showwarning("Register USB", f"Too many wrong passwords. Locked for {lock // 60 + 1} min.", parent=root)
        return False
    d = Dialog(root, "Register USB", step=1)
    label(d.body, f"This USB: {usb.vendor} {usb.product}  (drive {usb.drive})")
    if not usb.serial:
        label(d.body, "The serial number of this USB cannot be read, so it cannot be registered.", fg="#C62828", font=FONT_B)
        d.button("Close", None, default=True)
        d.show()
        return False
    first = not wl.has_password
    label(d.body, "First registration. Set the password (at least 8 characters)." if first else "Enter the launch password.")
    pw1, pw2 = tk.StringVar(), tk.StringVar()
    tk.Entry(d.body, textvariable=pw1, show="●", font=FONT).pack(fill="x", pady=2)
    if first:
        tk.Entry(d.body, textvariable=pw2, show="●", font=FONT).pack(fill="x", pady=2)
    d.button("Cancel", None, default=True)
    d.button("Register", lambda: (pw1.get(), pw2.get()), primary=True)
    a = d.show()
    if not a:
        return False
    if first:
        if len(a[0]) < 8 or a[0] != a[1]:
            messagebox.showwarning("Register USB", "The password is shorter than 8 characters or the two entries differ.", parent=root)
            return False
        wl.set_password(a[0])
    elif not wl.verify_password(a[0]):
        messagebox.showwarning("Register USB", "Wrong password.", parent=root)
        return False
    wl.register(usb.serial, f"{usb.vendor} {usb.product}".strip())
    messagebox.showinfo("Register USB", "This USB has been registered.", parent=root)
    return True
