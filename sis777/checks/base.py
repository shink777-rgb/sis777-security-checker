"""Common parts of the check modules: run context (Ctx), Check base class, shared queries."""
from __future__ import annotations

import csv
import io
import os
from dataclasses import dataclass, field
from typing import Any, Callable

from ..core import reg
from ..core.ps import run_cmd, run_ps
from ..core.result import Result, Status
from ..core.sysinfo import PcInfo


@dataclass
class Ctx:
    cfg: dict
    pc: PcInfo
    tmp: str                                   # <system name>\tmp on the USB
    log: Callable[[str], None] = print
    ask: Callable[[str, Any], Any] = lambda kind, payload: None   # ask for a decision pop-up (worker thread → UI)
    history: Any = None                        # history.store.History
    inspection_type: str = "정기"
    cache: dict = field(default_factory=dict)
    cfg_dirty: bool = False                    # criteria.json must be saved (e.g. after picking SafeUSB)


class FixStepMixin:
    @staticmethod
    def step(r: Result, desc: str, before, after, key: str = "", risky: bool = False, irreversible: bool = False):
        from ..core.result import FixStep
        r.fix_plan.append(FixStep(desc, str(before), str(after), risky, irreversible, key or desc))


class Check:
    code = ""
    title = ""
    category = ""
    severity = "상"
    fixable = False
    guide = ""

    def new(self, **kw) -> Result:
        return Result(self.code, self.title, self.category, self.severity,
                      guide=kw.pop("guide", self.guide), fixable=self.fixable, **kw)

    def check(self, ctx: Ctx) -> Result:  # pragma: no cover - implemented by each item
        raise NotImplementedError

    def fix(self, ctx: Ctx, result: Result, journal, keys: set[str] | None = None) -> str:
        raise NotImplementedError("auto-fix is not supported for this item")


# ------------------------------------------------------------------ shared queries
def parse_secpol(text: str) -> dict:
    """Parse the [System Access] section of a secedit export."""
    out, sect = {}, ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            sect = line.strip("[]")
            continue
        if sect == "System Access" and "=" in line:
            k, v = (x.strip() for x in line.split("=", 1))
            try:
                out[k] = int(v)
            except ValueError:
                out[k] = v.strip('"')
    return out


def secpol(ctx: Ctx) -> dict:
    if "secpol" not in ctx.cache:
        path = os.path.join(ctx.tmp, "sis777_secexport.inf")
        rc, out = run_cmd(["secedit", "/export", "/cfg", path, "/areas", "SECURITYPOLICY", "/quiet"], 40)
        if rc != 0 or not os.path.exists(path):
            raise RuntimeError(f"secedit export failed: {out.strip()[:200]}")
        with open(path, "rb") as f:
            raw = f.read()
        os.remove(path)
        text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
        ctx.cache["secpol"] = parse_secpol(text)
    return ctx.cache["secpol"]


UNINSTALL = [r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
             r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
             r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall"]


def installed_programs(ctx: Ctx) -> list[dict]:
    if "programs" not in ctx.cache:
        seen, out = set(), []
        for base in UNINSTALL:
            for sk in reg.subkeys(base):
                p = f"{base}\\{sk}"
                name = reg.val(p, "DisplayName")
                if not name or name in seen or reg.val(p, "SystemComponent") == 1:
                    continue
                seen.add(name)
                out.append({"name": str(name), "publisher": str(reg.val(p, "Publisher", "") or ""),
                            "version": str(reg.val(p, "DisplayVersion", "") or "")})
        ctx.cache["programs"] = sorted(out, key=lambda x: x["name"].lower())
    return ctx.cache["programs"]


def processes(ctx: Ctx) -> set[str]:
    if "procs" not in ctx.cache:
        rc, out = run_cmd(["tasklist", "/fo", "csv", "/nh"], 20)
        names = set()
        if rc == 0:
            for row in csv.reader(io.StringIO(out)):
                if row:
                    names.add(row[0].lower())
        ctx.cache["procs"] = names
    return ctx.cache["procs"]


def services(ctx: Ctx) -> dict[str, dict]:
    if "services" not in ctx.cache:
        rows = run_ps("Get-CimInstance Win32_Service | Select-Object Name, DisplayName, StartMode, State")
        ctx.cache["services"] = {r["Name"].lower(): r for r in rows}
    return ctx.cache["services"]


def policy_managed(ctx: Ctx, present: bool) -> str:
    """On a domain-joined PC, a value under a Policies key means the item is managed by Group Policy."""
    return "그룹 정책 관리" if (present and ctx.pc.domain_joined) else ""


def contains_any(text: str, words: list[str]) -> str:
    t = text.lower()
    for w in words:
        if w and w.lower() in t:
            return w
    return ""


__all__ = ["Ctx", "Check", "FixStepMixin", "Result", "Status", "reg", "run_ps", "run_cmd", "secpol", "parse_secpol",
           "installed_programs", "processes", "services", "policy_managed", "contains_any"]
