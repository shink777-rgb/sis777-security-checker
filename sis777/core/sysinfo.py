"""Step 2, PC info: computer name, signed-in user SID, OS edition/build, IP, MAC, domain membership."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from . import reg
from .ps import PSError, run_ps

NT_CV = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
VIRTUAL_PAT = re.compile(r"hyper-v|vmware|virtualbox|vpn|tap-|wan miniport|bluetooth|loopback|virtual|npcap|wireguard|fortinet|anyconnect",
                         re.I)
MAC_RE = re.compile(r"^[0-9A-F]{2}(-[0-9A-F]{2}){5}$")


@dataclass
class Adapter:
    name: str
    desc: str
    mac: str
    ips: list[str] = field(default_factory=list)
    gateway: bool = False


@dataclass
class PcInfo:
    computer: str = ""
    user: str = ""
    user_sid: str = ""
    os_name: str = ""
    edition_id: str = ""
    display_version: str = ""
    build: int = 0
    ubr: int = 0
    installation_type: str = ""
    domain_joined: bool = False
    domain: str = ""
    adapters: list[Adapter] = field(default_factory=list)
    lang_mode: str = ""

    @property
    def is_win11(self) -> bool:
        return self.build >= 22000

    @property
    def os_label(self) -> str:
        base = "Windows 11" if self.is_win11 else "Windows 10"
        ed = {"Core": "Home", "CoreSingleLanguage": "Home", "Professional": "Pro", "Enterprise": "Enterprise",
              "EnterpriseS": "Enterprise LTSC", "IoTEnterpriseS": "IoT Enterprise LTSC", "Education": "Education",
              "ProfessionalEducation": "Pro Education", "ProfessionalWorkstation": "Pro for Workstations"}
        return f"{base} {ed.get(self.edition_id, self.edition_id)} {self.display_version}".strip()

    @property
    def ips(self) -> list[str]:
        return [ip for a in self.adapters for ip in a.ips]

    def default_mac(self) -> str:
        for a in self.adapters:
            if a.gateway:
                return a.mac
        return self.adapters[0].mac if self.adapters else ""


def norm_mac(m: str) -> str:
    h = re.sub(r"[^0-9A-Fa-f]", "", m or "").upper()
    return "-".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def console_user() -> tuple[str, str]:
    """(name, SID) of the console session user (owner of explorer.exe)."""
    try:
        import ctypes
        sess = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
    except Exception:  # noqa: BLE001
        sess = -1
    script = (
        "Get-CimInstance Win32_Process -Filter \"Name='explorer.exe'\" | ForEach-Object {"
        " $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner;"
        " $s = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid;"
        " [pscustomobject]@{Session=$_.SessionId; User=($o.Domain + '\\' + $o.User); Sid=$s.Sid} }")
    try:
        rows = run_ps(script)
    except PSError:
        rows = []
    rows = [r for r in rows if r.get("Sid")]
    pick = next((r for r in rows if r.get("Session") == sess), rows[0] if rows else None)
    if pick:
        return pick["User"], pick["Sid"]
    try:
        r = run_ps("$i=[Security.Principal.WindowsIdentity]::GetCurrent(); [pscustomobject]@{U=$i.Name;S=$i.User.Value}")
        return r[0]["U"], r[0]["S"]
    except (PSError, IndexError, KeyError):
        return os.environ.get("USERNAME", ""), ""


def adapters() -> list[Adapter]:
    script = (
        "$cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True';"
        "Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object {"
        " $a=$_; $c = $cfg | Where-Object { $_.InterfaceIndex -eq $a.ifIndex };"
        " [pscustomobject]@{Name=$a.Name; Desc=$a.InterfaceDescription; Mac=$a.MacAddress;"
        "  Ips=@($c.IPAddress | Where-Object { $_ -match '^\\d+\\.' }); Gw=[bool]($c.DefaultIPGateway)} }")
    out: list[Adapter] = []
    try:
        rows = run_ps(script)
    except PSError:
        rows = []
    if not rows:  # fallback: WMI only
        try:
            rows = run_ps("Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {"
                          "[pscustomobject]@{Name=$_.Description; Desc=$_.Description; Mac=$_.MACAddress;"
                          " Ips=@($_.IPAddress | Where-Object { $_ -match '^\\d+\\.' }); Gw=[bool]($_.DefaultIPGateway)} }")
        except PSError:
            rows = []
    for r in rows:
        mac = norm_mac(r.get("Mac", ""))
        if not mac or VIRTUAL_PAT.search(f"{r.get('Name', '')} {r.get('Desc', '')}"):
            continue
        ips = r.get("Ips") or []
        out.append(Adapter(r.get("Name", ""), r.get("Desc", ""), mac, ips if isinstance(ips, list) else [ips],
                           bool(r.get("Gw"))))
    out.sort(key=lambda a: (not a.gateway, a.name))
    return out


def all_physical_macs() -> list[str]:
    """MACs of all physical adapters, connected or not (used to find this PC's folder)."""
    try:
        rows = run_ps("Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Select-Object MacAddress")
    except PSError:
        rows = []
    return [m for m in (norm_mac(r.get("MacAddress", "")) for r in rows) if m]


def collect() -> PcInfo:
    info = PcInfo()
    info.computer = os.environ.get("COMPUTERNAME", "")
    info.user, info.user_sid = console_user()
    reg.set_user_sid(info.user_sid or None)
    info.edition_id = reg.val(NT_CV, "EditionID", "") or ""
    info.display_version = reg.val(NT_CV, "DisplayVersion", "") or reg.val(NT_CV, "ReleaseId", "") or ""
    info.build = int(reg.val(NT_CV, "CurrentBuildNumber", 0) or reg.val(NT_CV, "CurrentBuild", 0) or 0)
    info.ubr = int(reg.val(NT_CV, "UBR", 0) or 0)
    info.installation_type = reg.val(NT_CV, "InstallationType", "") or ""
    info.os_name = reg.val(NT_CV, "ProductName", "") or ""
    try:
        cs = run_ps("Get-CimInstance Win32_ComputerSystem | Select-Object PartOfDomain, Domain")[0]
        info.domain_joined = bool(cs.get("PartOfDomain"))
        info.domain = cs.get("Domain", "") if info.domain_joined else ""
    except (PSError, IndexError):
        pass
    info.adapters = adapters()
    from .ps import language_mode
    info.lang_mode = language_mode()
    return info
