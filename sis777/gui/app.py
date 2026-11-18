"""Main window — automatic run progress screen. Work runs in a worker thread; UI updates go through a queue."""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .. import APP_NAME_EN, APP_VERSION
from ..core.result import Status
from ..core.runner import STEPS, Pipeline, Stopped
from ..core.storage import RESTORED_SUFFIX
from . import popups

NAVY, BLUE, ORANGE, GREEN, RED, GRAY = "#1F3864", "#1967D2", "#E67C00", "#2E7D32", "#C62828", "#787878"
UI_FONT = "Malgun Gothic"
FONT = (UI_FONT, 10)
STATE = {"wait0": ("○", "Waiting", GRAY), "run": ("▶", "Running", BLUE), "wait": ("▶", "Needs input", ORANGE),
         "done": ("✓", "Done", GREEN), "skip": ("–", "Skipped", GRAY), "error": ("!", "Error", RED)}
COLOR = {Status.GOOD: GREEN, Status.PARTIAL: ORANGE, Status.VULN: RED, Status.EXCEPT: "#6A1B9A",
         Status.MANUAL: ORANGE, Status.NA: GRAY, Status.ERROR: GRAY}


class Bridge:
    """Worker thread → UI. The UI interface used by Pipeline."""

    def __init__(self, app: "App"):
        self.app, self.q = app, app.q

    def step(self, n, state):
        self.q.put(("step", n, state))

    def progress(self, pct, text):
        self.q.put(("progress", pct, text))

    def result(self, r):
        self.q.put(("result", r))

    def log(self, text):
        self.q.put(("log", text))

    def ask(self, popup, payload):
        box = {"ev": threading.Event(), "answer": None}
        self.q.put(("ask", popup, payload, box))
        box["ev"].wait()
        return box["answer"]

    def check_pause(self):
        while self.app.paused.is_set() and not self.app.stop_flag.is_set():
            self.app.resume_ev.wait(0.2)
        if self.app.stop_flag.is_set():
            raise Stopped()


class App(tk.Tk):
    def __init__(self, usb):
        super().__init__()
        self.usb = usb
        self.title(f"{APP_NAME_EN} — automatic run  (v{APP_VERSION})")
        self.geometry("1180x760")
        self.minsize(1000, 640)
        self.q: queue.Queue = queue.Queue()
        self.paused, self.stop_flag, self.resume_ev = threading.Event(), threading.Event(), threading.Event()
        self.pipeline: Pipeline | None = None
        self.worker: threading.Thread | None = None
        self.rows: dict[str, object] = {}
        self._build()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(80, self._poll)

    def on_close(self):
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("Exit", "An inspection is running. Exit anyway?\nIf auto-fix is running, only some changes may be applied.", default="no"):
                return
        self.destroy()

    # ------------------------------------------------------------ layout
    def _build(self):
        top = tk.Frame(self, bg="#EBEEF3", padx=12, pady=8)
        top.pack(fill="x", padx=10, pady=(10, 4))
        self.info = tk.Label(top, text=f"USB {self.usb.drive} ({self.usb.vendor} {self.usb.product})  |  Press [Start] to run the 9 steps in order.",
                             bg="#EBEEF3", font=FONT, anchor="w")
        self.info.pack(side="left", fill="x", expand=True)
        bar = tk.Frame(top, bg="#EBEEF3")
        bar.pack(side="right")
        self.b_start = tk.Button(bar, text="Start", width=9, bg=BLUE, fg="white", font=(UI_FONT, 10, "bold"), command=self.start)
        self.b_pause = tk.Button(bar, text="Pause", width=9, command=self.pause, state="disabled")
        self.b_stop = tk.Button(bar, text="Stop", width=7, command=self.stop, state="disabled")
        self.b_restore = tk.Button(bar, text="Restore", width=8, command=self.restore)
        self.b_hist = tk.Button(bar, text="History", width=9, command=self.show_history)
        self.b_usb = tk.Button(bar, text="Register USB", width=11, command=self.usb_settings)
        self.b_pw = tk.Button(bar, text="Change password", width=14, command=self.change_password)
        for b in (self.b_start, self.b_pause, self.b_stop, self.b_restore, self.b_hist, self.b_usb, self.b_pw):
            b.pack(side="left", padx=2)

        mid = tk.Frame(self)
        mid.pack(fill="both", expand=True, padx=10)
        left = tk.Frame(mid, width=300)
        left.pack(side="left", fill="y", padx=(0, 10))
        tk.Label(left, text="Steps", font=(UI_FONT, 12, "bold"), fg=NAVY, anchor="w").pack(fill="x", pady=(6, 4))
        self.step_rows = []
        for i, name in enumerate(STEPS, 1):
            f = tk.Frame(left, pady=5, padx=6)
            f.pack(fill="x")
            ic = tk.Label(f, text="○", fg=GRAY, font=("Segoe UI Symbol", 12, "bold"), width=2)
            ic.pack(side="left")
            nm = tk.Label(f, text=f"{i}. {name}", font=(UI_FONT, 11), anchor="w", width=24)
            nm.pack(side="left")
            st = tk.Label(f, text="Waiting", fg=GRAY, font=FONT)
            st.pack(side="right")
            self.step_rows.append((f, ic, nm, st))

        right = tk.Frame(mid)
        right.pack(side="left", fill="both", expand=True)
        tk.Label(right, text="Overall progress", font=(UI_FONT, 12, "bold"), fg=NAVY, anchor="w").pack(fill="x", pady=(6, 4))
        self.pbar = ttk.Progressbar(right, maximum=100)
        self.pbar.pack(fill="x")
        self.cur = tk.Label(right, text="Waiting", font=FONT, anchor="w", fg="#444")
        self.cur.pack(fill="x", pady=4)
        tk.Label(right, text="Item results (double-click for details)", font=(UI_FONT, 12, "bold"), fg=NAVY, anchor="w").pack(fill="x", pady=(6, 4))
        cols = ("code", "title", "mark", "status", "current")
        self.tv = ttk.Treeview(right, columns=cols, show="headings", height=12)
        for c, t, w in (("code", "Code", 70), ("title", "Item", 260), ("mark", "Mark", 50), ("status", "Result", 100), ("current", "Current value", 420)):
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="center" if c in ("code", "mark", "status") else "w")
        for s, col in COLOR.items():
            self.tv.tag_configure(s.value, foreground=col)
        self.tv.pack(fill="both", expand=True)
        self.tv.bind("<Double-1>", self.detail)

        tk.Label(self, text="Log", font=(UI_FONT, 12, "bold"), fg=NAVY, anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        self.logbox = tk.Text(self, height=7, bg="#1E1E1E", fg="#C8E6C8", font=("Consolas", 9), relief="flat")
        self.logbox.pack(fill="x", padx=10, pady=(0, 10))

    # ------------------------------------------------------------ buttons
    def start(self):
        if self.worker and self.worker.is_alive():
            return
        self.tv.delete(*self.tv.get_children())
        self.rows.clear()
        for i in range(1, 10):
            self._set_step(i, "wait0")
        self.stop_flag.clear()
        self.paused.clear()
        self.pipeline = Pipeline(Bridge(self), self.usb)
        self.worker = threading.Thread(target=self._work, daemon=True)
        self.worker.start()
        self.b_start.config(state="disabled")
        self.b_pause.config(state="normal", text="Pause")
        self.b_stop.config(state="normal")
        self.b_restore.config(state="disabled"); self.b_pw.config(state="disabled")

    def _work(self):
        try:
            self.pipeline.run()
        finally:
            self.q.put(("finished",))

    def pause(self):
        if self.paused.is_set():
            self.paused.clear()
            self.resume_ev.set()
            self.b_pause.config(text="Pause")
        else:
            self.resume_ev.clear()
            self.paused.set()
            self.b_pause.config(text="Resume")

    def stop(self):
        if messagebox.askyesno("Stop", "Stop the run?\nChanges already made are kept and can be reverted with [Restore].", default="no"):
            self.stop_flag.set()
            self.resume_ev.set()

    def _folder(self):
        from ..core.storage import PcFolder, find_known
        from ..core.sysinfo import all_physical_macs
        if self.pipeline and self.pipeline.folder:
            return self.pipeline.folder
        name = find_known(self.usb.root, all_physical_macs())
        return PcFolder(self.usb.root, name) if name else None

    def restore(self):
        from ..core.backup import restore
        folder = self._folder()
        bdir = folder.latest_backup_dir() if folder else ""
        if not bdir:
            messagebox.showinfo("Restore", "There is no auto-fix backup for this PC.")
            return
        if not messagebox.askyesno("Restore", f"Revert the last auto-fix ({os.path.basename(bdir)})?", default="no"):
            return
        msgs = restore(bdir, folder.path("tmp"))
        os.rename(bdir, bdir + RESTORED_SUFFIX)
        for m in msgs:
            self._log(m)
        messagebox.showinfo("Restore", "\n".join(msgs[:25]) or "Nothing to revert.")

    def usb_settings(self):
        """Optional: register this USB and turn 'run only from registered USB drives' on/off (password required)."""
        from ..core.usbguard import Whitelist
        wl = Whitelist()
        state = "on" if wl.required else "off"
        if not messagebox.askyesno("Register USB (optional)", f"'Run only from registered USB drives': {state}\nRegistered USB drives: {len(wl.data['devices'])}\n\n"
                                   "Register this USB and change the setting? (password required)", default="no"):
            return
        if not popups.p10(self, wl, self.usb):
            return
        on = messagebox.askyesno("Register USB (optional)", "Allow the program to run only from registered USB drives?\n"
                                 "If you choose [No], it runs from any external USB drive.", default="no")
        wl.set_required(on)
        self._log(f"USB registered; registered-USB restriction: {'on' if on else 'off'}")

    def change_password(self):
        from ..core.usbguard import Whitelist
        if popups.change_password(self, Whitelist()):
            self._log("Launch password changed")

    def show_history(self):
        from ..history.store import History
        folder = self._folder()
        if not folder or not os.path.exists(folder.path("data", "history.db")):
            messagebox.showinfo("History", "No inspection history for this PC.")
            return
        h = History(folder.path("data", "history.db"))
        rows = h.runs()
        h.close()
        w = tk.Toplevel(self)
        w.title(f"History — {folder.name}")
        tv = ttk.Treeview(w, columns=("id", "at", "type", "score", "done"), show="headings", height=15)
        for c, t in (("id", "No."), ("at", "Date/time"), ("type", "Type"), ("score", "Score"), ("done", "Completed")):
            tv.heading(c, text=t)
        for r in rows:
            tv.insert("", "end", values=(r[0], r[1], r[2], r[3] if r[3] is not None else "", "Yes" if r[5] else "Stopped"))
        tv.pack(fill="both", expand=True, padx=8, pady=8)

    def detail(self, _e=None):
        sel = self.tv.selection()
        if not sel or not self.pipeline:
            return
        r = next((x for x in self.pipeline.results if x.code == sel[0]), None) or self.rows.get(sel[0])
        if not r:
            return
        text = (f"[{r.code}] {r.title}  ({r.category}, severity {r.severity})\n\nResult: {r.mark} {r.status.value}\n"
                f"Current: {r.current}\nCriterion: {r.expected}\n" + (f"Note: {r.note}\n" if r.note else "")
                + (f"Managed by: {r.managed}\n" if r.managed else "") + "\nEvidence:\n  " + "\n  ".join(r.evidence)
                + f"\n\nHow to fix:\n  {r.guide}")
        w = tk.Toplevel(self)
        w.title(f"{r.code} details")
        t = tk.Text(w, width=100, height=24, font=FONT, wrap="word")
        t.insert("1.0", text)
        t.config(state="disabled")
        t.pack(fill="both", expand=True, padx=8, pady=8)

    # ------------------------------------------------------------ queue handling
    def _set_step(self, n, state):
        f, ic, nm, st = self.step_rows[n - 1]
        sym, txt, col = STATE[state]
        bg = {"run": "#E3EEFC", "wait": "#FFF0DC"}.get(state, self.cget("bg"))
        for w in (f, ic, nm, st):
            w.config(bg=bg)
        ic.config(text=sym, fg=col)
        st.config(text=txt, fg=col)
        nm.config(font=(UI_FONT, 11, "bold" if state in ("run", "wait") else "normal"))

    def _log(self, text):
        self.logbox.insert("end", text + "\n")
        self.logbox.see("end")

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "step":
                    self._set_step(msg[1], msg[2])
                elif kind == "progress":
                    self.pbar["value"] = msg[1]
                    self.cur.config(text=f"Now: {msg[2]}")
                elif kind == "result":
                    r = msg[1]
                    vals = (r.code, r.title, r.mark, r.status.value + (f" ({r.managed})" if r.managed else ""), r.current)
                    if self.tv.exists(r.code):
                        self.tv.item(r.code, values=vals, tags=(r.status.value,))
                    else:
                        self.tv.insert("", "end", iid=r.code, values=vals, tags=(r.status.value,))
                    self.tv.see(r.code)
                    self.rows[r.code] = r
                elif kind == "log":
                    self._log(msg[1])
                elif kind == "ask":
                    self._answer(*msg[1:])
                elif kind == "finished":
                    self.b_start.config(state="normal", text="Run again")
                    self.b_pause.config(state="disabled")
                    self.b_stop.config(state="disabled")
                    self.b_restore.config(state="normal"); self.b_pw.config(state="normal")
                    if self.pipeline and self.pipeline.ctx:
                        pc, info = self.pipeline.ctx.pc, self.pipeline.pcinfo
                        self.info.config(text=f"System: {info.get('system_name', '')}  |  Asset no.: {info.get('asset_no', '')}  |  "
                                              f"MAC: {info.get('mac', '')}  |  {pc.os_label}")
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _answer(self, popup, payload, box):
        try:
            if popup == "P-02":
                pc = payload
                a = popups.p02(self, pc)
                if a:
                    self.info.config(text=f"System: {a['system_name']}  |  Asset no.: {a['asset_no']}  |  MAC: {a['mac']}  |  "
                                          f"Type: {a['type']}  |  {pc['os']}")
            elif popup == "P-03":
                a = popups.p03(self, payload)
            elif popup == "P-04":
                a = popups.p04(self, payload, on_stop=lambda: (self.stop_flag.set(), self.resume_ev.set()))
            elif popup == "P-05":
                a = popups.p05(self, payload)
            elif popup == "P-06":
                a = popups.p06(self, payload)
            elif popup == "P-08":
                a = popups.p08(self, payload)
            elif popup == "P-09":
                a = popups.p09(self, payload)
            elif popup == "P-11":
                a = popups.p11(self, payload)
            else:  # P-07, ERROR, USB_REMOVED
                a = popups.info(self, payload)
        except Exception as e:  # noqa: BLE001  — a pop-up error must not stall the worker thread
            self._log(f"Pop-up error: {e}")
            a = None
        box["answer"] = a
        box["ev"].set()
