"""Unit tests for verdict logic, storage and the pipeline (run without Windows; Windows-only tests are skipped).

Run: python -m unittest discover -s tests -v
"""
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sis777.checks import pc04, pc05, pc06, pc08, pc11, pc16  # noqa: E402
from sis777.checks.av import decode_state  # noqa: E402
from sis777.checks.base import Check, FixStepMixin, parse_secpol  # noqa: E402
from sis777.core import runner, storage  # noqa: E402
from sis777.core.result import Result, Status, score  # noqa: E402
from sis777.core.sysinfo import Adapter, PcInfo, norm_mac  # noqa: E402
from sis777.core.usbguard import UsbInfo, Whitelist, parse_descriptor  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def R(code, st, sev="상"):
    return Result(code, code, "c", sev, status=st)


class Judge(unittest.TestCase):
    def test_score(self):
        s, c = score([R("a", Status.GOOD), R("b", Status.PARTIAL), R("c", Status.VULN, "하"), R("d", Status.NA)])
        self.assertEqual(s, round((3 + 1.5) / 7 * 100))
        self.assertEqual(c["해당 없음"], 1)

    def test_secpol(self):
        t = "[Unicode]\nUnicode=yes\n[System Access]\nMinimumPasswordAge = 0\nMaximumPasswordAge = -1\nPasswordComplexity = 1\nNewAdministratorName = \"Admin\"\n[Event Audit]\nAuditSystemEvents = 0"
        d = parse_secpol(t)
        self.assertEqual(d["MaximumPasswordAge"], -1)
        self.assertEqual(d["NewAdministratorName"], "Admin")
        self.assertNotIn("AuditSystemEvents", d)

    def test_pc04(self):
        shares = [{"Name": "ADMIN$", "Type": 2147483648}, {"Name": "C$", "Type": 2147483648},
                  {"Name": "IPC$", "Type": 2147483651}, {"Name": "Data", "Type": 0}]
        admin, user, ev = pc04.classify(shares, {"Data"})
        self.assertEqual(admin, ["ADMIN$", "C$"])
        self.assertEqual(ev, ["Data"])

    def test_pc05(self):
        rows = {"spooler": {"Name": "Spooler", "State": "Running", "StartMode": "Auto"},
                "remoteregistry": {"Name": "RemoteRegistry", "State": "Stopped", "StartMode": "Disabled"}}
        self.assertEqual(pc05.judge(rows, ["Spooler", "RemoteRegistry", "Alerter"])[0], Status.PARTIAL)
        self.assertEqual(pc05.judge(rows, ["RemoteRegistry"])[0], Status.GOOD)
        self.assertEqual(pc05.judge(rows, ["Alerter"])[0], Status.NA)

    def test_pc06(self):
        block = [{"name": "카카오톡", "display": ["KakaoTalk"], "process": ["kakaotalk.exe"]},
                 {"name": "Skype", "display": ["Skype"], "process": []}]
        progs = [{"name": "Skype version 8"}]
        self.assertEqual(pc06.find_messengers(progs, {"kakaotalk.exe"}, block, []), ["카카오톡 (실행 중)", "Skype"])
        self.assertEqual(pc06.find_messengers(progs, set(), block, ["Skype"]), [])

    def test_pc08(self):
        out = ("Windows 부팅 로더\n-------------------\n식별자 {11111111-1111-1111-1111-111111111111}\ndescription Windows 11\n\n"
               "Windows 부팅 로더\n-------------------\n식별자 {22222222-2222-2222-2222-222222222222}\ndescription Windows Recovery Environment\nwinpe Yes\n")
        self.assertEqual(pc08.count_os_loaders(out), (1, 1))

    def test_av_state(self):
        self.assertEqual(decode_state(0x061100), (True, True))     # Defender on, up to date
        self.assertEqual(decode_state(0x060110), (False, False))
        self.assertEqual(decode_state(0x041000), (True, True))

    def test_pc11(self):
        table = [{"name": "W11 24H2", "build": 26100, "group": "enterprise", "end": "2027-10-12"},
                 {"name": "W11 LTSC", "build": 26100, "group": "ltsc", "end": "2029-10-09"}]
        self.assertEqual(pc11.lookup(table, 26100, "Enterprise")["end"], "2027-10-12")
        self.assertEqual(pc11.lookup(table, 26100, "EnterpriseS")["end"], "2029-10-09")
        self.assertIsNone(pc11.lookup(table, 26100, "Professional"))

    def test_pc11_real_table(self):
        import json
        t = json.load(open(os.path.join(ROOT, "config", "criteria.json"), encoding="utf-8"))["os_support"]["table"]
        self.assertEqual(pc11.lookup(t, 19044, "IoTEnterpriseS")["end"], "2032-01-13")   # IoT LTSC 2021
        self.assertEqual(pc11.lookup(t, 19044, "EnterpriseS")["end"], "2027-01-12")      # LTSC 2021
        self.assertEqual(pc11.lookup(t, 26100, "IoTEnterpriseS")["end"], "2034-10-10")   # IoT LTSC 2024
        self.assertEqual(pc11.lookup(t, 26200, "Professional")["end"], "2027-10-12")     # 25H2 Pro
        self.assertEqual(pc11.lookup(t, 26200, "Enterprise")["end"], "2028-10-10")       # 25H2 Enterprise
        self.assertEqual(pc11.lookup(t, 22631, "Education")["end"], "2026-11-10")        # 23H2 Education
        self.assertEqual(len({(r["build"], r["group"]) for r in t}), len(t))             # no duplicates

    def test_pc16(self):
        ok = {"ScreenSaveActive": "1", "ScreenSaverIsSecure": "1", "ScreenSaveTimeOut": "600", "SCRNSAVE.EXE": "x.scr"}
        self.assertEqual(pc16.judge(ok, 600)[0], Status.GOOD)
        self.assertEqual(pc16.judge({**ok, "ScreenSaveTimeOut": "900"}, 600)[0], Status.PARTIAL)
        self.assertEqual(pc16.judge({**ok, "ScreenSaveActive": "0"}, 600)[0], Status.VULN)

    def test_selfcheck_and_exception(self):
        rs = [R("PC-20", Status.MANUAL), R("PC-10", Status.GOOD), R("PC-17", Status.VULN), R("PC-04", Status.VULN)]
        runner.apply_selfcheck(rs, {"PC-20": "yes", "PC-10p": "no", "PC-17p": "no"})
        self.assertEqual([r.status for r in rs[:3]], [Status.GOOD, Status.PARTIAL, Status.VULN])
        runner.apply_exceptions(rs, {"PC-04": {"reason": "제조사 미지원"}})
        self.assertEqual(rs[3].status, Status.EXCEPT)
        self.assertEqual(rs[3].mark, "X")

    def test_mac(self):
        self.assertEqual(norm_mac("00:1a:2b:3c:4d:5e"), "00-1A-2B-3C-4D-5E")
        self.assertEqual(norm_mac("bad"), "")


class Usb(unittest.TestCase):
    def test_descriptor(self):
        raw = bytearray(64)
        struct.pack_into("<II", raw, 0, 1, 64)
        raw[10] = 1
        struct.pack_into("<IIIII", raw, 12, 40, 46, 0, 52, 7)
        raw[40:46] = b"Sams\x00\x00"
        raw[46:52] = b"T7\x00\x00\x00\x00"
        raw[52:60] = b"S3Z9ABC\x00"
        d = parse_descriptor(bytes(raw))
        self.assertEqual((d["bus_type"], d["vendor"], d["product"], d["serial"]), (7, "Sams", "T7", "S3Z9ABC"))

    def test_whitelist(self):
        with tempfile.TemporaryDirectory() as t:
            wl = Whitelist(os.path.join(t, "w.json"))
            wl.set_password("password1")
            self.assertTrue(wl.verify_password("password1"))
            wl.register("abc 123", "test")
            self.assertTrue(Whitelist(os.path.join(t, "w.json")).is_registered("ABC123"))
            self.assertFalse(wl.is_registered("XYZ"))
            self.assertFalse(wl.required)          # default: optional feature off
            wl.set_required(True)
            self.assertTrue(Whitelist(os.path.join(t, "w.json")).required)
            for _ in range(5):
                wl.verify_password("wrong")
            self.assertGreater(wl.locked_seconds(), 0)
            with open(os.path.join(t, "w.json"), encoding="utf-8") as f:
                self.assertNotIn("ABC123", f.read())


class Storage(unittest.TestCase):
    def test_name_folder(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(storage.sanitize_name(' 운영 PC:1/2 . '), "운영 PC_1_2")
            self.assertEqual(storage.sanitize_name("CON"), "CON_")
            name, _ = storage.resolve_folder(t, "운영PC", "00-1A-2B-3C-4D-5E", ["00-1A-2B-3C-4D-5E"], "")
            self.assertEqual(name, "운영PC")
            f = storage.PcFolder(t, name, "00-1A-2B-3C-4D-5E")
            self.assertTrue(f.is_new)
            f.save_pcinfo({"system_name": "운영PC", "mac": "00-1A-2B-3C-4D-5E", "macs": ["00-1A-2B-3C-4D-5E"]})
            self.assertEqual(storage.find_known(t, ["11-11-11-11-11-11", "00-1A-2B-3C-4D-5E"]), "운영PC")
            self.assertEqual(storage.PcFolder.peek(t, "운영PC")["system_name"], "운영PC")
            self.assertFalse(storage.PcFolder(t, "운영PC").is_new)
            # renaming the system renames the folder
            name2, _ = storage.resolve_folder(t, "개발PC", "00-1A-2B-3C-4D-5E", ["00-1A-2B-3C-4D-5E"], "운영PC")
            self.assertEqual(name2, "개발PC")
            self.assertTrue(os.path.isdir(os.path.join(t, "개발PC", "data")))
            # another PC with the same name gets a MAC suffix
            name3, _ = storage.resolve_folder(t, "개발PC", "AA-BB-CC-DD-EE-FF", ["AA-BB-CC-DD-EE-FF"], "")
            self.assertEqual(name3, "개발PC_EE-FF")

    def test_legacy_mac_folder(self):
        with tempfile.TemporaryDirectory() as t:
            storage.PcFolder(t, "00-1A-2B-3C-4D-5E").save_pcinfo({"system_name": "A"})
            known = storage.find_known(t, ["00-1A-2B-3C-4D-5E"])
            self.assertEqual(known, "00-1A-2B-3C-4D-5E")
            name, _ = storage.resolve_folder(t, "A", "00-1A-2B-3C-4D-5E", ["00-1A-2B-3C-4D-5E"], known)
            self.assertEqual(name, "A")
            self.assertFalse(os.path.exists(os.path.join(t, "00-1A-2B-3C-4D-5E")))

    def test_restored_backup_skipped(self):
        with tempfile.TemporaryDirectory() as t:
            f = storage.PcFolder(t, "00-1A-2B-3C-4D-5E")
            for d in ("20261117_100000", "20261117_100000_원복완료"):
                os.makedirs(f.path("backup", d))
                open(f.path("backup", d, "journal.json"), "w").write("[]")
            self.assertTrue(f.latest_backup_dir().endswith("20261117_100000"))
            os.rename(f.path("backup", "20261117_100000"), f.path("backup", "20261117_100000_x"))
            os.remove(f.path("backup", "20261117_100000_x", "journal.json"))
            self.assertEqual(f.latest_backup_dir(), "")


class Pc19(unittest.TestCase):
    def _ctx(self, answer):
        from sis777.checks.base import Ctx
        c = Ctx(cfg={"safeusb": {"product_names": [], "service_names": []}}, pc=PcInfo(), tmp=".",
                ask=lambda kind, payload: answer)
        c.cache.update({"programs": [{"name": "SafeUSB Agent 3.1"}],
                        "services": {"safeusbsvc": {"Name": "SafeUsbSvc", "DisplayName": "SafeUSB Service", "State": "Running"}}})
        return c

    def test_later_is_manual(self):
        from sis777.checks.pc19 import PC19
        self.assertEqual(PC19().check(self._ctx(None)).status, Status.MANUAL)

    def test_not_installed(self):
        from sis777.checks.pc19 import PC19
        self.assertEqual(PC19().check(self._ctx({"not_installed": True})).status, Status.VULN)

    def test_pick_saves_names(self):
        from sis777.checks.pc19 import PC19
        ctx = self._ctx({"product": "SafeUSB Agent 3.1", "service": "SafeUsbSvc"})
        self.assertEqual(PC19().check(ctx).status, Status.GOOD)
        self.assertTrue(ctx.cfg_dirty)
        self.assertEqual(ctx.cfg["safeusb"]["service_names"], ["SafeUsbSvc"])


# ------------------------------------------------------------------ evidence command syntax
class EvidenceCommands(unittest.TestCase):
    def _cmds(self):
        from types import SimpleNamespace
        from sis777.core import config
        from sis777.evidence.commands import COMMANDS
        ctx = SimpleNamespace(pc=PcInfo(computer="T", user="t'user", user_sid="S-1-5-21-1-2-3-1001"),
                              tmp=tempfile.gettempdir(), cfg=config.load(), history=None)
        return {c: f(ctx) for c, f in COMMANDS.items()}

    def test_no_glued_statements(self):
        """Catch command fragments glued together without ';' (e.g. ''$k=...)."""
        for code, cmd in self._cmds().items():
            for bad in ("''$", "'" * 3, ";;", "; ;"):
                self.assertNotIn(bad, cmd, f"{code}: {bad}")

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell 필요")
    def test_powershell_parse(self):
        """On Windows, parse the 21 evidence commands and the PC-00 script with the PowerShell parser."""
        import subprocess
        from sis777.evidence.capture import PC00_BODY, WIN32, build_inner
        scripts = {c: build_inner("T", ["h"], cmd, "x.txt", "x.done") for c, cmd in self._cmds().items()}
        scripts["PC-00"] = WIN32 + "$png1='a'; $png2='b'; $txt='c'; $usb='E:'; $head=@('h')\n" + PC00_BODY
        with tempfile.TemporaryDirectory() as t:
            for code, sc in scripts.items():
                fn = os.path.join(t, code + ".ps1")
                with open(fn, "w", encoding="utf-8-sig") as f:
                    f.write(sc)
                chk = ("$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('" + fn +
                       "',[ref]$null,[ref]$e); $e | ForEach-Object { $_.Message + ' @' + $_.Extent.StartLineNumber }")
                out = subprocess.run(["powershell", "-NoProfile", "-Command", chk], capture_output=True,
                                     stdin=subprocess.DEVNULL, timeout=60).stdout.decode("utf-8", "replace").strip()
                self.assertEqual(out, "", f"{code} 문법 오류: {out}")


# ------------------------------------------------------------------ security review fixes
class Security(unittest.TestCase):
    def test_ps_quote_smart_quotes(self):
        from sis777.core.ps import ps_quote
        for q in ("'", "\u2018", "\u2019", "\u201a", "\u201b"):
            out = ps_quote(f"a{q}; calc; {q}")
            self.assertEqual(out.count(q) % 2, 0 if q != "'" else 0)
            self.assertIn(q + q, out)
        self.assertNotIn("\x00", ps_quote("a\x00b"))

    def test_ps_regex_escapes(self):
        from sis777.core.ps import ps_regex
        self.assertEqual(ps_regex(["LINE (", "a|b"]), "'LINE\\ \\(|a\\|b'")

    def test_run_cmd_full_path(self):
        from sis777.core import ps
        self.assertTrue(ps.sysexe("net").lower().endswith(os.path.join("", "net.exe")))
        import ntpath
        self.assertTrue(ntpath.isabs(ps.sysexe("secedit")))

    def test_restore_rejects_tampered_journal(self):
        from sis777.core import backup
        ok = {"type": "reg", "code": "PC-03", "path": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole",
              "name": "SecurityLevel", "existed": True, "old_value": 1, "old_type": 4}
        self.assertEqual(backup.validate_entry(ok), "")
        bad = [dict(ok, path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", name="x"),
               dict(ok, old_type=7),
               dict(ok, old_value="calc"),
               {"type": "firewall", "code": "PC-15", "profile": "Public; calc", "old": False},
               {"type": "service", "code": "PC-05", "name": "a$(calc)", "old_start": "Auto", "old_state": "Running"},
               {"type": "secedit", "code": "PC-01", "old": {"NewAdministratorName": 1}},
               {"type": "localuser", "code": "PC-01", "name": "a;b", "old_never_expires": True},
               {"type": "reg", "code": "PC-16", "path": r"HKU\S-1-5-21-1-2-3-1001\Control Panel\Desktop",
                "name": "SCRNSAVE.EXE", "existed": True, "old_value": r"C:\evil.exe", "old_type": 1},
               {"type": "unknown"}]
        for b in bad:
            self.assertNotEqual(backup.validate_entry(b), "", b)
        with tempfile.TemporaryDirectory() as t:
            with open(os.path.join(t, "journal.json"), "w", encoding="utf-8") as f:
                json.dump(bad[:1], f)
            msgs = backup.restore(t, t)
            self.assertIn("restore skipped", msgs[0])

    def test_service_name_validated(self):
        from sis777.core import backup
        with tempfile.TemporaryDirectory() as t:
            j = backup.Journal(t)
            with self.assertRaises(RuntimeError):
                j.set_service("PC-05", "x' -or 1=1 -or Name='y")
            with self.assertRaises(RuntimeError):
                j.firewall("PC-15", "Public;calc", False)

    @unittest.skipUnless(os.name == "nt", "Windows 필요")
    def test_bitlocker_status_runs(self):
        """On Windows, the BitLocker check returns on/off/unknown without errors."""
        from sis777.core import usbguard
        self.assertIn(usbguard.bitlocker_status("C:"), ("on", "off", "unknown"))
        ok, msg = usbguard.protection_status("C:\\")
        self.assertIsInstance(ok, bool)

    def test_launch_password_lockout(self):
        from sis777.core.usbguard import LOCK_FAILS, Whitelist
        with tempfile.TemporaryDirectory() as t:
            wl = Whitelist(os.path.join(t, "w.json"))
            self.assertFalse(wl.has_password)
            wl.set_password("abcd1234")
            wl2 = Whitelist(os.path.join(t, "w.json"))          # survives reload
            self.assertTrue(wl2.verify_password("abcd1234"))
            for i in range(LOCK_FAILS - 1):
                self.assertFalse(wl2.verify_password("wrong"))
                self.assertEqual(wl2.fails_left(), LOCK_FAILS - 1 - i)
            self.assertFalse(wl2.verify_password("wrong"))
            self.assertGreater(wl2.locked_seconds(), 0)
            self.assertFalse(wl2.verify_password("abcd1234"))     # even the right password is refused while locked
            with open(os.path.join(t, "w.json"), encoding="utf-8") as f:
                self.assertNotIn("abcd1234", f.read())             # plain password never stored

    def test_csv_formula(self):
        from sis777.report.csv_report import safe
        self.assertEqual(safe("=cmd|'/c calc'!A1"), "'=cmd|'/c calc'!A1")
        self.assertEqual(safe("양호"), "양호")

    def test_no_script_files_on_usb(self):
        """Evidence capture must not create .ps1 files in the USB tmp folder."""
        import inspect
        from sis777.evidence import capture
        src = inspect.getsource(capture)
        self.assertNotIn('".ps1"', src)
        self.assertNotIn(" -File ", src)


# ------------------------------------------------------------------ simulated pipeline run
class FakeCheck(FixStepMixin, Check):
    def __init__(self, code, st, fixable=False, sev="상"):
        self.code, self.title, self.category, self.severity, self.fixable = code, f"항목 {code}", "분류", sev, fixable
        self.st, self.fixed = st, False

    def check(self, ctx):
        r = self.new(status=Status.GOOD if self.fixed else self.st, current="모의")
        if self.fixable and not self.fixed and self.st != Status.GOOD:
            self.step(r, "설정", "전", "후")
        return r

    def fix(self, ctx, result, journal, keys=None):
        self.fixed = True
        return "모의 설정"


class FakeUI:
    def __init__(self):
        self.asked, self.logs, self.steps = [], [], {}

    def step(self, n, s):
        self.steps[n] = s

    def progress(self, *a):
        pass

    def result(self, r):
        pass

    def log(self, t):
        self.logs.append(t)

    def check_pause(self):
        pass

    def ask(self, popup, payload):
        self.asked.append(popup)
        if popup == "P-02":
            return {"system_name": "모의 시스템", "purpose": "테스트", "asset_no": "A-1", "mac": payload["mac"], "type": payload["type"]}
        if popup == "P-03":
            return {"answer": "yes", "apply_rest": True}
        if popup == "P-04":
            return [(r["code"], r["key"]) for r in payload["rows"]]
        return "ok"


class StopUI(FakeUI):
    """User presses [Stop] in P-04."""
    def __init__(self):
        super().__init__()
        self.stop = False

    def check_pause(self):
        if self.stop:
            raise runner.Stopped()

    def ask(self, popup, payload):
        if popup == "P-04":
            self.asked.append(popup)
            self.stop = True
            return None
        return super().ask(popup, payload)


def fake_capture_item(ctx, folder, r, phase, info):
    fn = folder.path("evidence", f"{r.code}_{phase.replace(' ', '')}_x.png")
    open(fn, "wb").close()
    return {"png": fn, "txt": "", "error": "" if r.code != "PC-05" else "모의 실패"}


def fake_capture_pc00(folder, pcinfo=None, pc=None):
    a, b = folder.path("evidence", "PC-00_시스템정보_x_1.png"), folder.path("evidence", "PC-00_시스템정보_x_2.png")
    return {"png": a, "pngs": [a, b], "txt": "", "error": ""}


class PipelineSim(unittest.TestCase):
    def _run(self, ui, checks, t):
        pc = PcInfo(computer="TESTPC", build=26100, edition_id="Enterprise", display_version="24H2",
                    adapters=[Adapter("이더넷", "Intel", "00-1A-2B-3C-4D-5E", ["10.0.0.5"], True)])
        patches = {"collect": lambda: pc, "all_physical_macs": lambda: ["00-1A-2B-3C-4D-5E"],
                   "can_write": lambda root: (True, ""), "usb_present": lambda root: True,
                   "protection_status": lambda root: (True, ""),
                   "ALL": checks, "BY_CODE": {c.code: c for c in checks}}
        saved = {k: getattr(runner, k) for k in patches}
        for k, v in patches.items():
            setattr(runner, k, v)
        from sis777.evidence import capture
        ev_saved = (capture.capture_item, capture.capture_pc00)
        capture.capture_item = fake_capture_item          # no real windows
        capture.capture_pc00 = fake_capture_pc00
        try:
            p = runner.Pipeline(ui, UsbInfo(True, "E:", t + os.sep, "USB", "SER1", "V", "P"))
            p.run()
        finally:
            for k, v in saved.items():
                setattr(runner, k, v)
            capture.capture_item, capture.capture_pc00 = ev_saved
        return p

    def test_stop_at_p04(self):
        checks = [FakeCheck(f"PC-{i:02d}", Status.GOOD) for i in range(1, 23)]
        checks[11] = FakeCheck("PC-12", Status.VULN, fixable=True, sev="중")
        with tempfile.TemporaryDirectory() as t:
            ui = StopUI()
            self._run(ui, checks, t)
            base = os.path.join(t, "모의 시스템")
            self.assertEqual(os.listdir(os.path.join(base, "reports")), [])      # no reports after a stop
            self.assertFalse(os.path.exists(os.path.join(base, "data", "running.json")))  # stopped before any change → no unfinished marker
            self.assertNotIn("P-09", ui.asked)
            self.assertFalse(checks[11].fixed)

    def test_full_run(self):
        checks = [FakeCheck(f"PC-{i:02d}", Status.GOOD) for i in range(1, 23)]
        checks[11] = FakeCheck("PC-12", Status.VULN, fixable=True, sev="중")
        checks[19] = FakeCheck("PC-20", Status.MANUAL)
        with tempfile.TemporaryDirectory() as t:
            ui = FakeUI()
            p = self._run(ui, checks, t)
            self.assertEqual(ui.steps, {i: "done" for i in range(1, 10)}, "\n".join(ui.logs[-15:]))
            by = {r.code: r for r in p.results}
            self.assertEqual(by["PC-12"].status, Status.GOOD)   # re-checked after auto-fix
            self.assertEqual(by["PC-20"].status, Status.GOOD)   # self-check answered 'yes'
            base = os.path.join(t, "모의 시스템")
            files = os.listdir(os.path.join(base, "reports"))
            from sis777.report.docx_form import template_available
            self.assertEqual(len(files), 3 if template_available() else 2, files)
            if template_available():   # the checklist form is not part of the public source
                docx = [f for f in files if f.endswith(".docx")][0]
                with zipfile.ZipFile(os.path.join(base, "reports", docx)) as z:
                    xml = z.read("word/document.xml").decode("utf-8")
                self.assertNotIn("{{", xml)
                self.assertIn("모의 시스템", xml)
                self.assertIn("00-1A-2B-3C-4D-5E", xml)
                self.assertIn("[별지] 증빙 목록", xml)
                self.assertIn("PC-00_시스템정보_x_1.png, PC-00_시스템정보_x_2.png", xml)
                self.assertIn("PC-12_조치전_x.png", xml)
                self.assertIn("PC-12_조치후_x.png", xml)
                self.assertIn("캡쳐 실패", xml)
                self.assertNotIn("PC-20_조치전", xml)                     # PC-20 left blank
                self.assertNotIn("PC-20_", " ".join(os.listdir(os.path.join(base, "evidence"))))
            self.assertTrue(os.path.exists(os.path.join(base, "data", "history.db")))
            self.assertFalse(os.path.exists(os.path.join(base, "data", "running.json")))
            self.assertIn("P-09", ui.asked)


if __name__ == "__main__":
    unittest.main()
