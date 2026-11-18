"""Run-from-USB check and registered USB serials.

Order of checks
 1) reject if the executable path is UNC (\\\\server\\...)
 2) drive type: reject network, optical and subst drives
 3) BusType via IOCTL_STORAGE_QUERY_PROPERTY → only USB (7) is allowed; virtual disks (15) are rejected
 4) optionally, the serial number from the same call must be in the registered list (usb_whitelist.json)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass

BUS_NAMES = {0: "Unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "IEEE1394", 5: "SSA", 6: "FibreChannel",
             7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual",
             15: "FileBackedVirtual", 16: "Spaces", 17: "NVMe", 18: "SCM", 19: "UFS"}
BUS_USB = 7

# Built-in key that makes hand-editing the registered list harder (raw serials are never stored).
# This is a usage-policy aid, not a security boundary: anyone with the source or the binary can read it.
_HMAC_KEY = b"SIS777-usb-whitelist-v1::7f3a9c1e5b"
LOCK_FAILS = 5
LOCK_SECONDS = 600


@dataclass
class UsbInfo:
    ok: bool
    drive: str = ""          # 'E:'
    root: str = ""           # 'E:\\'
    bus: str = ""
    serial: str = ""
    vendor: str = ""
    product: str = ""
    reason: str = ""


def program_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------- low-level Windows
def _query_storage(drive: str) -> dict:
    """Read STORAGE_DEVICE_DESCRIPTOR of the \\\\.\\X: device."""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    CreateFileW = k32.CreateFileW
    CreateFileW.restype = wintypes.HANDLE
    CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    DeviceIoControl = k32.DeviceIoControl
    DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    INVALID = wintypes.HANDLE(-1).value
    h = CreateFileW(f"\\\\.\\{drive}", 0, 3, None, 3, 0, None)  # access 0, share R|W, OPEN_EXISTING
    if h == INVALID or h is None:
        raise OSError(f"cannot open device ({ctypes.get_last_error()})")
    try:
        query = (ctypes.c_ubyte * 12)()  # PropertyId=0(StorageDeviceProperty), QueryType=0
        buf = (ctypes.c_ubyte * 4096)()
        ret = wintypes.DWORD(0)
        IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
        if not DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, query, 12, buf, 4096, ctypes.byref(ret), None):
            raise OSError(f"device query failed ({ctypes.get_last_error()})")
        raw = bytes(buf[: max(ret.value, 32)])
    finally:
        k32.CloseHandle(h)
    return parse_descriptor(raw)


def parse_descriptor(raw: bytes) -> dict:
    """Parse STORAGE_DEVICE_DESCRIPTOR (separate function so it can be unit-tested)."""
    import struct

    def s_at(off: int) -> str:
        if not off or off >= len(raw):
            return ""
        end = raw.find(b"\x00", off)
        return raw[off:end if end >= 0 else None].decode("ascii", "ignore").strip()

    vendor_off, product_off, _rev, serial_off, bus = struct.unpack_from("<IIIII", raw, 12)
    return {"removable": bool(raw[10]), "bus_type": bus, "vendor": s_at(vendor_off),
            "product": s_at(product_off), "serial": s_at(serial_off)}


def _drive_type(root: str) -> int:
    import ctypes
    return ctypes.windll.kernel32.GetDriveTypeW(root)


def _is_subst(drive: str) -> bool:
    import ctypes
    buf = ctypes.create_unicode_buffer(1024)
    if ctypes.windll.kernel32.QueryDosDeviceW(drive, buf, 1024):
        return buf.value.startswith("\\??\\")
    return False


def _bus_by_powershell(letter: str) -> tuple[int, str]:
    from .ps import run_ps
    rows = run_ps(f"$p=Get-Partition -DriveLetter {letter}; $d=Get-Disk -Number $p.DiskNumber;"
                  "[pscustomobject]@{Bus=[string]$d.BusType; Serial=[string]$d.SerialNumber}")
    if not rows:
        return 0, ""
    name = rows[0].get("Bus", "")
    code = {v: k for k, v in BUS_NAMES.items()}.get(name, 0)
    return code, (rows[0].get("Serial") or "").strip()


# ---------------------------------------------------------------- launch location
def check_launch_location(exe_dir: str | None = None) -> UsbInfo:
    exe_dir = exe_dir or program_dir()
    if exe_dir.startswith("\\\\"):
        return UsbInfo(False, reason="Started from a network path (UNC).")
    drive = os.path.splitdrive(exe_dir)[0].upper()
    if not drive:
        return UsbInfo(False, reason="Cannot determine the drive the program was started from.")
    root = drive + "\\"
    if os.name != "nt":
        return UsbInfo(False, drive, root, reason="Runs on Windows only.")
    dtype = _drive_type(root)
    if dtype == 4:
        return UsbInfo(False, drive, root, reason="Started from a network drive.")
    if dtype == 5:
        return UsbInfo(False, drive, root, reason="Started from a CD/DVD drive.")
    if _is_subst(drive):
        return UsbInfo(False, drive, root, reason="Started from a virtual (subst) drive.")
    try:
        d = _query_storage(drive)
        bus, serial = d["bus_type"], d["serial"]
        vendor, product = d["vendor"], d["product"]
    except OSError:
        try:
            bus, serial = _bus_by_powershell(drive[0])
            vendor = product = ""
        except Exception as e:  # noqa: BLE001
            return UsbInfo(False, drive, root, reason=f"Cannot determine how the drive is connected: {e}")
    bus_name = BUS_NAMES.get(bus, str(bus))
    if bus != BUS_USB:
        return UsbInfo(False, drive, root, bus_name, serial, vendor, product,
                       reason=f"Not an external USB drive (bus type: {bus_name}).")
    return UsbInfo(True, drive, root, bus_name, serial, vendor, product)


def can_write(root: str) -> tuple[bool, str]:
    test = os.path.join(root, f".sis777_write_test_{os.getpid()}")
    try:
        with open(test, "w", encoding="ascii") as f:
            f.write("ok")
        os.remove(test)
    except OSError as e:
        return False, f"Cannot write to the USB (write-protected or blocked by media control): {e}"
    try:
        import shutil
        free = shutil.disk_usage(root).free
        if free < 20 * 1024 * 1024:
            return False, "Less than 20 MB free on the USB."
    except OSError:
        pass
    return True, ""


PROTECT_GUIDE = ("Protect the USB with a BitLocker password (set it up on Windows Pro/Enterprise/Education; "
                 "afterwards it can be unlocked with the password on Home too).\n"
                 "1) In File Explorer, right-click the USB drive ({root}) → Turn on BitLocker\n"
                 "2) Choose 'Use a password to unlock the drive' → enter a password (8+ characters)\n"
                 "3) Save or print the recovery key somewhere other than this PC\n"
                 "4) Choose 'Encrypt used disk space only' and 'Compatible mode' → start (do not remove the USB until it finishes)\n"
                 "From then on the USB opens only after the password is entered.")
RESIDUAL_NOTE = ("USB is protected by a BitLocker password. While it is unlocked, other programs on this PC can still write to it, "
                 "so remove the USB as soon as the inspection is finished.")


def filesystem(root: str) -> str:
    if os.name != "nt":
        return ""
    import ctypes
    fs = ctypes.create_unicode_buffer(64)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(root, None, 0, None, None, None, fs, 64)
    return fs.value if ok else ""


def bitlocker_status(drive: str) -> str:
    """BitLocker state of the USB: 'on' (encrypted, protection on) / 'off' / 'unknown'."""
    if os.name != "nt":
        return "unknown"
    from .ps import PSError, ps_quote, run_ps
    script = ("$v = Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume "
              f"-ErrorAction Stop | Where-Object DriveLetter -eq {ps_quote(drive)}; "
              "if (-not $v) { 'off' } else { $c = Invoke-CimMethod -InputObject $v -MethodName GetConversionStatus; "
              "if ($v.ProtectionStatus -eq 1 -or $c.ConversionStatus -eq 1) { 'on' } else { 'off' } }")
    try:
        out = run_ps(script, timeout=20, as_json=False).strip().lower()
    except PSError:
        return "unknown"
    return out if out in ("on", "off") else "unknown"


def protection_status(root: str, prog_dir: str | None = None) -> tuple[bool, str]:
    """Whether the USB itself is password-protected (BitLocker To Go).

    The program runs with administrator rights, so a lost or borrowed USB must not let anyone change
    the program, its settings or the backup records. A password on the USB itself is recommended.
    """
    if os.name != "nt":
        return True, ""
    st = bitlocker_status(os.path.splitdrive(root)[0].upper())
    if st == "on":
        return True, RESIDUAL_NOTE
    if st == "unknown":
        return False, "Could not read the BitLocker state of the USB (BitLocker components may be missing on this PC)."
    return False, "The USB has no BitLocker password. If it is lost, anyone can open and change the program, its settings and the results."


def usb_present(root: str) -> bool:
    return os.path.exists(root)


# ---------------------------------------------------------------- registered list
class Whitelist:
    """usb_whitelist.json in the program folder — serials are stored only as HMAC values; also holds the launch password hash."""

    def __init__(self, path: str | None = None):
        self.path = path or os.path.join(program_dir(), "usb_whitelist.json")
        self.data = {"password": None, "devices": [], "fails": 0, "lock_until": 0, "required": False}
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    self.data.update(json.load(f))
            except (OSError, ValueError):
                pass

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def digest(serial: str) -> str:
        norm = "".join(serial.split()).upper()
        return hmac.new(_HMAC_KEY, norm.encode("utf-8"), hashlib.sha256).hexdigest()

    def is_registered(self, serial: str) -> bool:
        if not serial:
            return False
        d = self.digest(serial)
        return any(hmac.compare_digest(d, x.get("hmac", "")) for x in self.data["devices"])

    @property
    def required(self) -> bool:
        """Run only from registered USB drives (optional, off by default — any external USB drive works)."""
        return bool(self.data.get("required")) and bool(self.data["devices"])

    def set_required(self, on: bool) -> None:
        self.data["required"] = bool(on)
        self.save()

    @property
    def has_password(self) -> bool:
        return bool(self.data.get("password"))

    def set_password(self, pw: str) -> None:
        salt = secrets.token_hex(16)
        self.data["password"] = {"salt": salt, "iter": 200_000,
                                 "hash": hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()}
        self.save()

    def locked_seconds(self) -> int:
        return max(0, int(self.data.get("lock_until", 0) - time.time()))

    def verify_password(self, pw: str) -> bool:
        if self.locked_seconds():
            return False
        p = self.data.get("password")
        if not p:
            return False
        h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(p["salt"]), p["iter"]).hex()
        ok = hmac.compare_digest(h, p["hash"])
        if ok:
            self.data["fails"] = 0
        else:
            self.data["fails"] = self.data.get("fails", 0) + 1
            if self.data["fails"] >= LOCK_FAILS:
                self.data["lock_until"] = time.time() + LOCK_SECONDS
                self.data["fails"] = 0
        self.save()
        return ok

    def fails_left(self) -> int:
        """Attempts left before lock-out (0 while locked)."""
        if self.locked_seconds():
            return 0
        return max(0, LOCK_FAILS - int(self.data.get("fails", 0)))

    def register(self, serial: str, label: str) -> None:
        if not serial:
            raise ValueError("A USB whose serial number cannot be read cannot be registered.")
        if self.is_registered(serial):
            return
        self.data["devices"].append({"hmac": self.digest(serial), "label": label,
                                     "registered": time.strftime("%Y-%m-%d %H:%M")})
        self.save()

    def unregister(self, serial: str) -> None:
        d = self.digest(serial)
        self.data["devices"] = [x for x in self.data["devices"] if x.get("hmac") != d]
        self.save()
