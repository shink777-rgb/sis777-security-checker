"""SIS777 Security Checker entry point.

Start-up order (before the main window opens):
  1) must run from an external USB drive → otherwise P-00 notice and exit
  2) (optional) if 'run only from registered USB drives' is on, check the serial → otherwise P-00 [Register USB] → P-10
  3) administrator rights → otherwise offer to restart elevated
  4) launch password (P-12) — set on first run; 5 wrong attempts lock it for 10 minutes
"""
import os
import sys


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def relaunch_as_admin() -> None:
    import ctypes
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        exe, params = sys.executable, " ".join(f'"{a}"' for a in [os.path.abspath(sys.argv[0])] + sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)


def main() -> int:
    if os.name != "nt":
        print("Runs on Windows only.")
        return 1
    import tkinter as tk
    from tkinter import messagebox

    from sis777.core.usbguard import Whitelist, check_launch_location
    from sis777.gui import popups

    root = tk.Tk()
    root.withdraw()
    root.title("SIS777 Security Checker")

    usb = check_launch_location()
    if not usb.ok:
        popups.p00(root, usb.reason, can_register=False)
        return 2
    wl = Whitelist()
    if wl.required and not wl.is_registered(usb.serial):   # only when the registered-USB restriction is on (optional)
        reason = ("This USB is not registered." if usb.serial else "The serial number of this USB cannot be read, so it cannot be registered.")
        if popups.p00(root, reason, can_register=bool(usb.serial)) != "register" or not popups.p10(root, wl, usb):
            return 3
    if not is_admin():
        if messagebox.askyesno("Decision required — 1. Administrator rights",
                               "Inspection and auto-fix need administrator rights.\nRestart as administrator?", parent=root):
            relaunch_as_admin()
        return 4
    if not popups.p12_launch(root, wl):   # launch password (asked once, after elevation)
        return 5

    from sis777.report.docx_form import template_available, template_check
    try:
        missing = template_check() if template_available() else []   # no template → Word checklist is skipped
        if missing:
            messagebox.showwarning("Checklist template", "Placeholders missing in form_2026.docx: " + ", ".join(missing[:10]), parent=root)
    except OSError as e:
        messagebox.showwarning("Checklist template", f"Cannot open the template: {e}", parent=root)
    root.destroy()

    from sis777.gui.app import App
    App(usb).mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
