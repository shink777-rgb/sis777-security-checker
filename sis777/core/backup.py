"""Backup before auto-fix, and restore.

Every change first records the old value in journal.json, then makes the change, so the record survives
even if the USB is pulled half-way. Restore applies the records in reverse order.
"""
from __future__ import annotations

import json
import os
import time

import re

from . import reg
from .ps import PSError, ps_quote, run_cmd, run_ps

# ---------------------------------------------------------------- restore allow-list
# journal.json lives on the USB and can be edited by anyone, so restore only touches values this program changes.
ALLOWED_REG = {
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon": {"AutoAdminLogon"},
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole": {"SecurityLevel"},
    r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters": {"AutoShareWks", "AutoShareServer"},
    r"SOFTWARE\Policies\Microsoft\Edge": {"ClearCachedImagesAndFilesOnExit"},
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer": {"NoDriveTypeAutoRun"},
    r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services": {"fAllowToGetHelp"},
    r"SYSTEM\CurrentControlSet\Control\Remote Assistance": {"fAllowToGetHelp"},
}
ALLOWED_USER_REG = {   # under HKU\<SID>\
    r"Control Panel\Desktop": {"ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut", "SCRNSAVE.EXE"},
}
ALLOWED_TYPES = {reg.REG_SZ, reg.REG_EXPAND_SZ, reg.REG_DWORD} if hasattr(reg, "REG_EXPAND_SZ") else {1, 2, 4}
ALLOWED_SECPOL = {"MinimumPasswordAge", "MaximumPasswordAge", "MinimumPasswordLength", "PasswordComplexity",
                  "PasswordHistorySize", "LockoutBadCount", "ResetLockoutCount", "LockoutDuration"}
ALLOWED_PROFILES = {"Domain", "Private", "Public"}
_SID = re.compile(r"^S-1-5-21(-\d+){3,5}$")
_SVC = re.compile(r"^[A-Za-z0-9_.\-]{1,80}$")
_USER = re.compile(r"^[^\"/\\\[\]:;|=,+*?<>@\x00-\x1f]{1,64}$")


def reg_allowed(path: str, name: str) -> bool:
    """Whether a registry path/value name may be restored."""
    hive, _, sub = path.partition("\\")
    if hive.upper() in ("HKLM", "HKEY_LOCAL_MACHINE"):
        return name in {n for k, v in ALLOWED_REG.items() if k.lower() == sub.lower() for n in v}
    if hive.upper() in ("HKU", "HKEY_USERS"):
        sid, _, rest = sub.partition("\\")
        return bool(_SID.match(sid)) and name in {n for k, v in ALLOWED_USER_REG.items() if k.lower() == rest.lower() for n in v}
    return False


def validate_entry(e: dict) -> str:
    """Validate one journal entry. Returns a reason string if it is rejected, '' if it is fine."""
    t = e.get("type")
    if t in ("reg", "reg_del"):
        if not reg_allowed(str(e.get("path", "")), str(e.get("name", ""))):
            return "registry path not allowed"
        if (t == "reg_del" or e.get("existed")) and not e.get("secret"):
            if e.get("old_type") not in ALLOWED_TYPES:
                return "value type not allowed"
            v = e.get("old_value")
            if e.get("old_type") == reg.REG_DWORD and not (isinstance(v, int) and 0 <= v <= 0xFFFFFFFF):
                return "invalid DWORD value"
            if e.get("old_type") != reg.REG_DWORD and not (isinstance(v, str) and len(v) <= 260):
                return "invalid string value"
            if str(e.get("name", "")).upper() == "SCRNSAVE.EXE" and v and not str(v).lower().endswith(".scr"):
                return "not a screen saver (.scr) file"
        return ""
    if t == "service":
        if not _SVC.match(str(e.get("name", ""))):
            return "invalid service name"
        if e.get("old_start") not in ("Auto", "Manual", "Disabled", "Boot", "System") or e.get("old_state") not in (
                "Running", "Stopped", "Paused", "Start Pending", "Stop Pending", "Continue Pending", "Pause Pending", "Unknown", None, ""):
            return "invalid service state"
        return ""
    if t == "secedit":
        old = e.get("old")
        if not isinstance(old, dict) or not old:
            return "no security policy values"
        for k, v in old.items():
            if k not in ALLOWED_SECPOL or not isinstance(v, int) or not -1 <= v <= 999999:
                return f"security policy value not allowed ({k})"
        return ""
    if t == "localuser":
        return "" if _USER.match(str(e.get("name", ""))) and isinstance(e.get("old_never_expires"), bool) else "invalid account entry"
    if t == "firewall":
        return "" if e.get("profile") in ALLOWED_PROFILES and isinstance(e.get("old"), bool) else "invalid firewall profile"
    if t in ("share", "irreversible"):
        return ""
    return "unknown entry type"


class Journal:
    def __init__(self, folder: str):
        self.folder = folder
        self.path = os.path.join(folder, "journal.json")
        self.entries: list[dict] = []
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                self.entries = json.load(f)

    def _save(self) -> None:
        with open(self.path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(self.entries, f, ensure_ascii=False, indent=2)
        os.replace(self.path + ".tmp", self.path)

    def _add(self, code: str, entry: dict) -> None:
        entry.update({"code": code, "at": time.strftime("%Y-%m-%d %H:%M:%S")})
        self.entries.append(entry)
        self._save()

    def export_key(self, path: str) -> None:
        """Export a .reg file for reference (restore uses the journal)."""
        rp = reg.resolved(path)
        fn = os.path.join(self.folder, rp.replace("\\", "_").replace(" ", "")[:120] + ".reg")
        if not os.path.exists(fn):
            run_cmd(["reg", "export", rp, fn, "/y"], timeout=15)

    # ---------------------------------------------------------- changes
    def set_reg(self, code: str, path: str, name: str, value, typ: int, secret: bool = False) -> None:
        old = reg.get(path, name)
        self.export_key(path)
        self._add(code, {"type": "reg", "path": reg.resolved(path), "name": name, "existed": old is not None,
                         "old_value": None if (secret or old is None) else old[0],
                         "old_type": None if old is None else old[1],
                         "secret": secret, "new_value": value, "new_type": typ})
        reg.set_value(path, name, value, typ)

    def del_reg(self, code: str, path: str, name: str, secret: bool = False) -> None:
        old = reg.get(path, name)
        if old is None:
            return
        self._add(code, {"type": "reg_del", "path": reg.resolved(path), "name": name,
                         "old_value": None if secret else old[0], "old_type": old[1], "secret": secret})
        reg.delete_value(path, name)

    def set_service(self, code: str, name: str) -> None:
        if not _SVC.match(name):
            raise RuntimeError(f"invalid service name: {name[:40]}")
        rows = run_ps(f"Get-CimInstance Win32_Service | Where-Object Name -eq {ps_quote(name)} | Select-Object Name, StartMode, State")
        if not rows:
            return
        self._add(code, {"type": "service", "name": name, "old_start": rows[0]["StartMode"],
                         "old_state": rows[0]["State"]})
        run_ps(f"Stop-Service -Name {ps_quote(name)} -Force -ErrorAction SilentlyContinue;"
               f"Set-Service -Name {ps_quote(name)} -StartupType Disabled", as_json=False)

    def secedit(self, code: str, old: dict, new: dict, tmp_dir: str) -> None:
        self._add(code, {"type": "secedit", "old": old, "new": new})
        apply_secedit(new, tmp_dir)

    def local_user_never_expires(self, code: str, user: str, old: bool) -> None:
        self._add(code, {"type": "localuser", "name": user, "old_never_expires": old})
        run_ps(f"Set-LocalUser -Name {ps_quote(user)} -PasswordNeverExpires $false", as_json=False)

    def firewall(self, code: str, profile: str, old_enabled: bool) -> None:
        if profile not in ALLOWED_PROFILES:
            raise RuntimeError(f"invalid firewall profile: {profile[:20]}")
        self._add(code, {"type": "firewall", "profile": profile, "old": old_enabled})
        run_ps(f"Set-NetFirewallProfile -Profile {profile} -Enabled True", as_json=False)

    def share_delete(self, code: str, name: str, path: str) -> None:
        self._add(code, {"type": "share", "name": name, "path": path})
        rc, out = run_cmd(["net", "share", name, "/delete", "/y"])
        if rc != 0:
            raise RuntimeError(out.strip()[:200])

    def irreversible(self, code: str, desc: str, script: str) -> None:
        self._add(code, {"type": "irreversible", "desc": desc})
        run_ps(script, as_json=False, timeout=120)


def apply_secedit(values: dict, tmp_dir: str) -> None:
    """Apply [System Access] values with secedit /configure.

    The .inf file is created briefly in the USB tmp folder. Other programs can write to the USB,
    so its content is compared right before and right after applying; any change is reported as an error.
    """
    for k, v in values.items():
        if k not in ALLOWED_SECPOL or not isinstance(v, int) or not -1 <= v <= 999999:
            raise RuntimeError(f"security policy value not allowed: {k}")
    tag = os.urandom(6).hex()
    inf = os.path.join(tmp_dir, f"sis777_secpol_{tag}.inf")
    db = os.path.join(tmp_dir, f"sis777_secpol_{tag}.sdb")
    lines = ["[Unicode]", "Unicode=yes", "[System Access]"]
    lines += [f"{k} = {v}" for k, v in values.items()]
    lines += ["[Version]", 'signature="$CHICAGO$"', "Revision=1"]
    data = ("\r\n".join(lines) + "\r\n").encode("utf-16")
    with open(inf, "wb") as f:
        f.write(data)

    def same() -> bool:
        try:
            with open(inf, "rb") as f:
                return f.read() == data
        except OSError:
            return False
    try:
        if not same():
            raise RuntimeError("the security policy file changed before it was applied; aborted")
        rc, out = run_cmd(["secedit", "/configure", "/db", db, "/cfg", inf, "/areas", "SECURITYPOLICY", "/quiet"], 60)
        if not same():
            raise RuntimeError("the security policy file changed while it was applied — check the local security policy by hand")
        if rc != 0:
            raise RuntimeError(f"secedit failed: {out.strip()[:200]}")
    finally:
        for p in (inf, db, db.replace(".sdb", ".jfm")):
            try:
                os.remove(p)
            except OSError:
                pass


def restore(folder: str, tmp_dir: str, codes: set[str] | None = None) -> list[str]:
    """Revert the journal in reverse order. Returns a list of messages."""
    j = Journal(folder)
    msgs: list[str] = []
    for e in reversed(j.entries):
        if codes and e["code"] not in codes:
            continue
        t = e.get("type")
        bad = validate_entry(e)
        if bad:
            msgs.append(f"{e.get('code', '?')} restore skipped: {bad} (the backup record may have been tampered with)")
            continue
        try:
            if t in ("reg", "reg_del"):
                if e.get("secret"):
                    msgs.append(f"{e['code']} {e['name']}: secret value was not backed up, so it is not restored")
                    continue
                if t == "reg" and not e["existed"]:
                    reg.delete_value(e["path"], e["name"])
                else:
                    reg.set_value(e["path"], e["name"], e["old_value"], e["old_type"])
                msgs.append(f"{e['code']} {e['name']} restored")
            elif t == "service":
                mode = {"Auto": "Automatic", "Manual": "Manual", "Disabled": "Disabled"}.get(e["old_start"], "Manual")
                run_ps(f"Set-Service -Name {ps_quote(e['name'])} -StartupType {mode}", as_json=False)
                if e["old_state"] == "Running":
                    run_ps(f"Start-Service -Name {ps_quote(e['name'])}", as_json=False)
                msgs.append(f"{e['code']} service {e['name']} restored")
            elif t == "secedit":
                apply_secedit(e["old"], tmp_dir)
                msgs.append(f"{e['code']} security policy restored")
            elif t == "localuser":
                if e["old_never_expires"]:
                    run_ps(f"Set-LocalUser -Name {ps_quote(e['name'])} -PasswordNeverExpires $true", as_json=False)
                msgs.append(f"{e['code']} account {e['name']} restored")
            elif t == "firewall":
                if not e["old"]:
                    run_ps(f"Set-NetFirewallProfile -Profile {ps_quote(e['profile'])} -Enabled False", as_json=False)
                msgs.append(f"{e['code']} firewall {e['profile']} restored")
            elif t == "share":
                msgs.append(f"{e['code']} share {e['name']}: default shares come back after AutoShareWks is restored and the PC restarts")
            elif t == "irreversible":
                msgs.append(f"{e['code']} {e['desc']}: cannot be restored")
        except (PSError, OSError, RuntimeError) as ex:
            msgs.append(f"{e['code']} restore failed: {ex}")
    return msgs
