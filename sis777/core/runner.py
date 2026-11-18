"""Nine-step automatic run pipeline.

Independent of the GUI; it talks to the UI only through this interface:
  ui.step(n, state)      state: run | done | wait | skip | error
  ui.progress(pct, text)
  ui.result(result)      add/update an item result
  ui.log(text)
  ui.ask(popup_id, payload) -> answer   (decision pop-up; blocks until answered)
  ui.check_pause()       waits while paused, raises Stopped when stopped

Text that ends up in the reports and the official checklist (result values, notes, evidence notes,
output file names) stays in Korean on purpose: the checklist is a Korean form.
"""
from __future__ import annotations

import os
import time
import traceback

from .. import APP_VERSION
from ..checks import ALL, BY_CODE, SELF_CHECKS
from ..checks.base import Ctx
from ..history.store import History
from . import config
from .backup import Journal
from .result import Result, Status, score
from .storage import PcFolder, find_known, resolve_folder, sanitize_name
from .sysinfo import all_physical_macs, collect
from .usbguard import PROTECT_GUIDE, UsbInfo, can_write, protection_status, usb_present

STEPS = ["Check environment", "Collect PC info", "Confirm inspection info", "Check items", "Self-check answers",
         "Summary and score", "Auto-fix", "Re-check", "Save reports"]


class Stopped(Exception):
    pass


class UsbRemoved(Exception):
    pass


def apply_selfcheck(results: list[Result], answers: dict[str, str]) -> None:
    """Apply self-check answers. PC-20: yes→good / no→vulnerable. Procedures (PC-10, 11, 17): no turns good into partial."""
    by = {r.code: r for r in results}
    for q in SELF_CHECKS:
        a = answers.get(q["id"])
        r = by.get(q["code"])
        if r is None or a is None:
            continue
        if q["id"] == "PC-20":
            if a == "yes":
                r.status, r.current = Status.GOOD, "자가점검: 설정함"
            elif a == "no":
                r.status, r.current = Status.VULN, "자가점검: 설정 안 함"
            else:
                r.current = "자가점검: 나중에(미응답)"
        elif a == "no" and r.status == Status.GOOD:
            r.status = Status.PARTIAL
            r.note = (r.note + " / " if r.note else "") + "관리절차 미수립(자가점검)"
        elif a == "later":
            r.note = (r.note + " / " if r.note else "") + "관리절차 자가점검 미응답"


def apply_exceptions(results: list[Result], exceptions: dict) -> None:
    for r in results:
        e = exceptions.get(r.code)
        if e and r.status in (Status.VULN, Status.PARTIAL):
            r.status = Status.EXCEPT
            r.note = f"예외: {e.get('reason', '')}" + (f" / 보완: {e['measure']}" if e.get("measure") else "")


class Logger:
    def __init__(self, ui):
        self.ui, self.buf, self.fp = ui, [], None

    def open(self, path: str) -> None:
        self.fp = open(path, "a", encoding="utf-8")
        for line in self.buf:
            self.fp.write(line + "\n")
        self.buf.clear()
        self.fp.flush()

    def __call__(self, text: str) -> None:
        line = f"{time.strftime('%H:%M:%S')}  {text}"
        self.ui.log(line)
        if self.fp:
            try:
                self.fp.write(line + "\n")
                self.fp.flush()
            except OSError:
                pass
        else:
            self.buf.append(line)

    def close(self) -> None:
        if self.fp:
            try:
                self.fp.close()
            except OSError:
                pass
            self.fp = None


class Pipeline:
    def __init__(self, ui, usb: UsbInfo):
        self.ui, self.usb = ui, usb
        self.log = Logger(ui)
        self.results: list[Result] = []
        self.folder: PcFolder | None = None
        self.history: History | None = None
        self.ctx: Ctx | None = None
        self.pcinfo: dict = {}
        self.report_paths: list[str] = []
        self.cur = 1
        self.score_before = None
        self.reboot_now = False
        self.fix_started = False
        self.evidence: dict[str, dict] = {}

    # ------------------------------------------------------------ common
    def _guard(self) -> None:
        if not usb_present(self.usb.root):
            raise UsbRemoved()
        self.ui.check_pause()

    def _ask(self, popup: str, payload):
        self.ui.step(self.cur, "wait")
        ans = self.ui.ask(popup, payload)
        self.ui.step(self.cur, "run")
        if self.history:
            self.history.answer(popup, str(payload.get("title", "")) if isinstance(payload, dict) else "", ans)
        return ans

    def _step(self, n: int) -> None:
        self._guard()
        self.cur = n
        self.ui.step(n, "run")
        self.log(f"[Step {n}] {STEPS[n - 1]}")

    # ------------------------------------------------------------ run
    def run(self) -> None:
        self.cur = 1
        try:
            self._run()
        except Stopped:
            self.log("Stopped by the user." + (" Changes already made are kept and can be reverted with [Restore]." if self.fix_started else ""))
            self.ui.step(self.cur, "skip")
            if self.folder and not self.fix_started:
                self.folder.clear_running()
        except UsbRemoved:
            self.ui.step(self.cur, "error")
            self.ui.ask("USB_REMOVED", {"title": "USB removed", "message": "The USB was removed, so the run stopped. Unfinished work will be reported on the next run."})
            return
        except Exception as e:  # noqa: BLE001
            self.ui.step(self.cur, "error")
            self.log(f"Error: {e}")
            self.log(traceback.format_exc())
            self.ui.ask("ERROR", {"title": "Error", "message": str(e)})
        finally:
            self.log.close()
            for fn in (lambda: self.history and self.history.close(),
                       lambda: self.ctx and self.ctx.cfg_dirty and config.save(self.ctx.cfg)):
                try:
                    fn()
                except Exception:  # noqa: BLE001  — e.g. USB removed
                    pass

    def _run(self) -> None:
        ui = self.ui
        # 1. Environment (USB, registered serial and admin rights are already checked in main) — can we write?
        self._step(1)
        ok, msg = can_write(self.usb.root)
        if not ok:
            raise RuntimeError(msg)
        self.log(f"USB {self.usb.drive} ({self.usb.vendor} {self.usb.product}, {self.usb.bus}) OK, program {APP_VERSION}")
        prot, pmsg = protection_status(self.usb.root)
        if not prot:
            self.log(f"[Security warning] {pmsg}")
            guide = PROTECT_GUIDE.format(root=self.usb.drive)
            self.log("[How to set a USB password] " + guide.replace("\n", " / "))
            self._ask("P-07", {"title": "USB password recommended", "message": pmsg + "\n\nThe inspection can continue.\n\n" + guide})
        else:
            self.log(pmsg or "USB protection checked")
        ui.step(1, "done")

        # 2. Collect PC info
        self._step(2)
        ui.progress(3, "Collecting PC info…")
        pc = collect()
        pc_macs = all_physical_macs() or [a.mac for a in pc.adapters]
        self.log(f"{pc.computer} / {pc.os_label} / user {pc.user} / IP {', '.join(pc.ips)} / domain {pc.domain or 'none'}")
        if pc.installation_type.lower() == "server":
            raise RuntimeError("Server editions of Windows are not supported.")
        if pc.lang_mode not in ("FullLanguage", "Unknown"):
            self.log(f"PowerShell language mode {pc.lang_mode}: some items may show as check errors.")
        ui.step(2, "done")

        # 3. Inspection info (P-02) → storage folder
        self._step(3)
        known = find_known(self.usb.root, pc_macs)
        saved = PcFolder.peek(self.usb.root, known) if known else {}
        saved_mac = saved.get("mac", "")
        payload = {
            "title": "Confirm inspection info", "adapters": [(a.mac, a.name, ", ".join(a.ips)) for a in pc.adapters],
            "mac": saved_mac if saved_mac in pc_macs else pc.default_mac(), "is_new": not known,
            "computer": pc.computer, "os": pc.os_label, "folder": known,
            "system_name": saved.get("system_name", ""), "purpose": saved.get("purpose", ""),
            "asset_no": saved.get("asset_no", ""), "type": "신규" if not known else "정기"}
        while True:
            ans = self._ask("P-02", payload)
            if not ans:
                raise Stopped()
            if sanitize_name(ans.get("system_name", "")):
                break
            payload.update({k: ans.get(k, "") for k in ("system_name", "purpose", "asset_no", "type")})
            self._ask("P-07", {"title": "System name required", "message": "The system name is used as the storage folder name on the USB, so it is required."})
        name, note = resolve_folder(self.usb.root, ans["system_name"], ans["mac"], pc_macs, known)
        self.folder = PcFolder(self.usb.root, name, ans["mac"])
        self.log.open(self.folder.path("logs", f"실행로그_{time.strftime('%Y%m%d_%H%M%S')}.log"))
        if note:
            self.log(note)
        unfinished = self.folder.unfinished()
        self.pcinfo = self.folder.load_pcinfo()
        self.pcinfo.update({k: ans[k] for k in ("system_name", "purpose", "asset_no")})
        self.pcinfo["mac"] = ans["mac"]
        self.pcinfo["macs"] = sorted(set(pc_macs) | {ans["mac"]})
        self.folder.save_pcinfo(self.pcinfo)
        self.folder.clean_tmp()
        self.history = History(self.folder.path("data", "history.db"))
        self.history.start(ans["type"], pc.computer, ans["mac"], pc.os_label)
        self.ctx = Ctx(cfg=config.load(), pc=pc, tmp=self.folder.path("tmp"), log=self.log,
                       ask=lambda kind, payload: self._ask(kind, payload), history=self.history,
                       inspection_type=ans["type"])
        self.folder.mark_running("inspection")
        if unfinished:
            self._ask("P-07", {"title": "Unfinished work", "message":
                               f"The '{unfinished.get('what')}' work of the previous run ({unfinished.get('at')}) did not finish. "
                               "Check the results and use [Restore] if needed."})
        self.log(f"Storage folder: {self.folder.base} ({'new PC' if self.folder.is_new else 'known PC'})")
        if self._evidence_on():
            ui.progress(8, "Capturing PC-00 system info screen…")
            from ..evidence.capture import capture_pc00
            r0 = capture_pc00(self.folder, self.pcinfo, self.ctx.pc)
            self._record_evidence("PC-00", "before", r0)
        ui.step(3, "done")

        # 4. Check items
        self._step(4)
        self.results = self._check_all(range(len(ALL)), base_pct=10, span=60)
        ui.step(4, "done")

        # 5. Self-check (P-03)
        self._step(5)
        answers: dict[str, str] = {}
        same_for_rest = None
        for i, q in enumerate(SELF_CHECKS):
            self._guard()
            a = same_for_rest or self._ask("P-03", {"title": "Self-check", "index": i + 1, "total": len(SELF_CHECKS), **q})
            if isinstance(a, dict):
                if a.get("apply_rest"):
                    same_for_rest = a["answer"]
                a = a["answer"]
            answers[q["id"]] = a or "later"
        apply_selfcheck(self.results, answers)
        apply_exceptions(self.results, self.pcinfo.get("exceptions", {}))
        for r in self.results:
            ui.result(r)
        ui.step(5, "done")

        # 6. Summary + "before" evidence capture
        self._step(6)
        if self._evidence_on():
            self._capture_all(self.results, "조치 전", base_pct=70, span=8)
        sc, counts = score(self.results)
        self.history.save_results("before", self.results)
        self.log(f"Results: good {counts['양호']}, partial {counts['부분 설정']}, vulnerable {counts['취약']}, "
                 f"exception {counts['예외']}, manual {counts['수동 확인']}, error {counts['점검 오류']} — score {sc}")
        self.score_before = sc
        ui.progress(75, f"Score {sc}")
        ui.step(6, "done")

        # 7. Auto-fix
        self._step(7)
        fixed = self._auto_fix()
        apply_exceptions(self.results, self.pcinfo.get("exceptions", {}))
        for r in self.results:
            ui.result(r)
        ui.step(7, "done" if fixed is not None else "skip")

        # 8. Re-check
        self._step(8)
        if fixed:
            idx = [i for i, c in enumerate(ALL) if c.code in fixed]
            self.ctx.cache.clear()
            new = {r.code: r for r in self._check_all(idx, base_pct=80, span=10)}
            self.results = [new.get(r.code, r) for r in self.results]
            apply_selfcheck(self.results, answers)
            apply_exceptions(self.results, self.pcinfo.get("exceptions", {}))
            for r in self.results:
                ui.result(r)
            if self._evidence_on():
                self._capture_all([r for r in self.results if r.code in fixed], "조치 후", base_pct=90, span=5)
            reboot = [r.code for r in new.values() if r.needs_reboot] + [c for c in fixed if fixed[c].get("reboot")]
            relogon = [c for c in fixed if fixed[c].get("relogon")]
            if reboot or relogon:
                a = self._ask("P-08", {"title": "Restart required", "reboot": sorted(set(reboot)), "relogon": relogon})
                self.reboot_now = a == "now"
            ui.step(8, "done")
        else:
            ui.step(8, "skip")

        # 9. Save
        self._step(9)
        sc, counts = score(self.results)
        self.history.save_results("after", self.results)
        self.history.finish(sc, counts)
        self.folder.clear_running()
        self._save_reports(sc, counts)
        ui.progress(100, "Done")
        remain = [f"{r.code} {r.title}" for r in self.results if r.status in (Status.VULN, Status.PARTIAL)]
        self._ask("P-09", {"title": "Inspection finished", "score_before": self.score_before, "score_after": sc,
                           "counts": counts, "remain": remain, "files": self.report_paths, "folder": self.folder.base})
        ui.step(9, "done")
        self.folder.clean_tmp()
        if getattr(self, "reboot_now", False):
            from .ps import run_cmd
            run_cmd(["shutdown", "/r", "/t", "30", "/c", "SIS777: restarting in 30 seconds to apply settings."])

    # ------------------------------------------------------------ evidence capture
    def _evidence_on(self) -> bool:
        return bool(self.ctx and self.ctx.cfg.get("evidence", {}).get("enabled", True))

    def _record_evidence(self, code: str, phase: str, res: dict) -> None:
        e = self.evidence.setdefault(code, {})
        pngs = res.get("pngs") or ([res["png"]] if res["png"] else [])
        e[phase] = ", ".join(os.path.basename(x) for x in pngs) or os.path.basename(res["txt"] or "")
        if res["error"]:
            e.setdefault("note", []).append("화면 캡쳐 실패, 텍스트만 저장" if res["txt"] else "캡쳐 실패")
            self.log(f"{code} evidence ({phase}) capture failed: {res['error']}")
        else:
            self.log(f"{code} evidence ({phase}) saved: {e[phase]}")

    def _capture_all(self, results, phase: str, base_pct: int, span: int) -> None:
        from ..evidence.capture import capture_item
        targets = [r for r in results if r.code != "PC-20"]
        for n, r in enumerate(targets):
            self._guard()
            self.ui.progress(base_pct + span * n // max(len(targets), 1), f"{r.code} capturing evidence ({phase})…")
            res = capture_item(self.ctx, self.folder, r, phase, self.pcinfo)
            self._record_evidence(r.code, "before" if phase == "조치 전" else "after", res)

    # ------------------------------------------------------------ item checks
    def _check_all(self, indexes, base_pct: int, span: int) -> list[Result]:
        out = []
        idx = list(indexes)
        for n, i in enumerate(idx):
            self._guard()
            chk = ALL[i]
            self.ui.progress(base_pct + span * n // max(len(idx), 1), f"Checking {chk.code} {chk.title}…")
            t0 = time.time()
            try:
                r = chk.check(self.ctx)
            except Exception as e:  # noqa: BLE001
                r = chk.new(status=Status.ERROR, current="점검 오류", note=str(e)[:200])
            self.log(f"{r.code}  {r.status.value}  {r.current[:80]}  ({time.time() - t0:.1f} s)")
            out.append(r)
            self.ui.result(r)
        return out

    # ------------------------------------------------------------ auto-fix
    def _auto_fix(self) -> dict | None:
        exc = self.pcinfo.get("exceptions", {})
        managed = [r for r in self.results if r.managed and r.status in (Status.VULN, Status.PARTIAL)]
        if managed:
            self._ask("P-07", {"title": "Managed items", "message": "These items are excluded from auto-fix because they are managed elsewhere: " + ", ".join(
                f"{r.code} ({r.managed})" for r in managed) + ". They are still reported on the checklist."})
        cand = [r for r in self.results if r.auto_fixable and r.code not in exc]
        if not cand:
            self.log("Nothing to auto-fix.")
            return None
        rows = [{"code": r.code, "title": r.title, "key": s.key, "desc": s.desc, "before": s.before,
                 "after": s.after, "risky": s.risky, "irreversible": s.irreversible} for r in cand for s in r.fix_plan]
        sel = self._ask("P-04", {"title": "Confirm auto-fix", "rows": rows})
        if not sel:
            self.log("Auto-fix skipped.")
            return None
        sel = {(c, k) for c, k in sel}
        # confirm risky items one by one (P-05)
        rest = None
        for row in rows:
            if (row["code"], row["key"]) in sel and (row["risky"] or row["irreversible"]):
                a = rest or self._ask("P-05", {"title": "Confirm risky item", **row})
                if isinstance(a, dict):
                    rest = a["answer"] if a.get("apply_rest") else None
                    a = a["answer"]
                if a != "yes":
                    sel.discard((row["code"], row["key"]))
        self.folder.mark_running("auto-fix")
        self.fix_started = True
        journal = Journal(self.folder.new_backup_dir())
        fixed: dict[str, dict] = {}
        for r in cand:
            keys = {k for c, k in sel if c == r.code}
            if not keys:
                continue
            while True:
                self._guard()
                try:
                    msg = BY_CODE[r.code].fix(self.ctx, r, journal, keys)
                    self.log(f"{r.code} auto-fix: {msg}")
                    self.history.action(r.code, "fix", msg)
                    fixed[r.code] = {"reboot": r.needs_reboot, "relogon": r.needs_relogon}
                    break
                except UsbRemoved:
                    raise
                except Exception as e:  # noqa: BLE001
                    self.log(f"{r.code} fix failed: {e}")
                    a = self._ask("P-06", {"title": "Fix failed", "code": r.code, "item": r.title, "error": str(e)[:300]})
                    if isinstance(a, dict) and a.get("answer") == "except":
                        self.pcinfo.setdefault("exceptions", {})[r.code] = {
                            "reason": a.get("reason", ""), "measure": a.get("measure", ""),
                            "vendor_doc": a.get("vendor_doc", False), "at": time.strftime("%Y-%m-%d")}
                        self.folder.save_pcinfo(self.pcinfo)
                        self.history.action(r.code, "except", a.get("reason", ""))
                        break
                    if a != "retry":
                        self.history.action(r.code, "skip", str(e)[:200])
                        break
        return fixed

    # ------------------------------------------------------------ save
    def _save_reports(self, sc, counts) -> None:
        from ..report import csv_report, docx_form, html_report
        stamp = time.strftime("%Y%m%d_%H%M")
        meta = {"pcinfo": self.pcinfo, "pc": self.ctx.pc, "type": self.ctx.inspection_type, "score": sc,
                "score_before": self.score_before, "counts": counts, "date": time.strftime("%Y-%m-%d"),
                "datetime": time.strftime("%Y-%m-%d %H:%M"), "usb": self.usb, "exceptions": self.pcinfo.get("exceptions", {}),
                "evidence": self.evidence, "evidence_enabled": self._evidence_on(), "folder": self.folder.name}
        targets = [
            ("HTML report", lambda: html_report.write(self.folder.path("reports", f"점검결과_{stamp}.html"), self.results, meta)),
            ("CSV", lambda: csv_report.write(self.folder.path("reports", f"점검결과_{stamp}.csv"), self.results, meta)),
        ]
        if docx_form.template_available():
            targets.append(("Word checklist", lambda: docx_form.write(
                self.folder.path("reports", f"보안점검표_{stamp[:8]}.docx"), self.results, meta)))
        else:
            self.log("Word checklist skipped: templates/form_2026.docx not found (see templates/README.md)")
        for name, fn in targets:
            try:
                self.report_paths.append(fn())
                self.log(f"{name} saved: {self.report_paths[-1]}")
            except Exception as e:  # noqa: BLE001
                self.log(f"{name} save failed: {e}")
