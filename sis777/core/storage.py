"""USB storage folders — one <system name> folder per PC at the root of the USB.

Whether a folder belongs to this PC is decided by the MAC addresses recorded in data\\pcinfo.json,
not by the folder name, so renaming the system or changing the main network adapter keeps using the same folder.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time

from .sysinfo import MAC_RE

SUBDIRS = ("data", "reports", "evidence", "backup", "logs", "tmp")
_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
RESTORED_SUFFIX = "_restored"
_RESTORED = (RESTORED_SUFFIX, "_원복완료")   # second one: folders made by v0.3.2 and earlier
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def sanitize_name(name: str) -> str:
    """Make a system name usable as a Windows folder name (invalid characters → _, trailing dots/spaces removed, reserved names avoided)."""
    n = _BAD.sub("_", (name or "").strip())
    n = re.sub(r"\s+", " ", n).rstrip(" .")[:60].rstrip(" .")
    if n.upper() in _RESERVED:
        n += "_"
    return n


def _read_pcinfo(folder: str) -> dict | None:
    try:
        with open(os.path.join(folder, "data", "pcinfo.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _macs_of(info: dict | None) -> set[str]:
    if not info:
        return set()
    return {m for m in [info.get("mac", ""), *info.get("macs", [])] if m}


def pc_folders(usb_root: str) -> list[tuple[str, dict]]:
    """Inspection data folders (folders containing data\\pcinfo.json) at the root of the USB."""
    out = []
    try:
        names = sorted(os.listdir(usb_root))
    except OSError:
        return out
    for n in names:
        full = os.path.join(usb_root, n)
        if os.path.isdir(full):
            info = _read_pcinfo(full)
            if info is not None:
                out.append((n, info))
    return out


def find_known(usb_root: str, pc_macs: list[str]) -> str:
    """Existing folder name for this PC: matched by the MACs in pcinfo, falling back to the old <MAC> folder layout."""
    macs = set(pc_macs)
    for n, info in pc_folders(usb_root):
        if _macs_of(info) & macs:
            return n
    for m in pc_macs:  # before v0.1.1: <MAC> folders
        if MAC_RE.match(m) and os.path.isdir(os.path.join(usb_root, m)):
            return m
    return ""


def resolve_folder(usb_root: str, system_name: str, mac: str, pc_macs: list[str], known: str) -> tuple[str, str]:
    """Folder name to use, plus a message for the log.

    - default: <system name>
    - if this PC's existing folder has another name (system renamed, old MAC folder), rename it
    - if a folder with that name belongs to another PC: <system name>_<last 5 chars of MAC>
    """
    target = sanitize_name(system_name)
    if not target:
        raise ValueError("The system name is empty, so no storage folder can be created.")
    macs = set(pc_macs) | {mac}

    def owned_by_other(name: str) -> bool:
        full = os.path.join(usb_root, name)
        if not os.path.exists(full) or name == known:
            return False
        return not (_macs_of(_read_pcinfo(full)) & macs)

    if owned_by_other(target):
        target = f"{target}_{mac[-5:]}"
    if known and known != target:
        if not os.path.exists(os.path.join(usb_root, target)):
            os.rename(os.path.join(usb_root, known), os.path.join(usb_root, target))
            return target, f"Renamed folder '{known}' to '{target}'."
        return known, f"Folder '{target}' already exists, so the existing folder '{known}' is kept."
    note = "" if target == sanitize_name(system_name) else f"Another PC already uses that name, so folder '{target}' is used."
    return target, note


class PcFolder:
    def __init__(self, usb_root: str, name: str, mac: str = ""):
        self.name = name
        self.mac = mac
        self.base = os.path.join(usb_root, name)
        self.is_new = not os.path.isdir(os.path.join(self.base, "data"))
        for d in SUBDIRS:
            os.makedirs(os.path.join(self.base, d), exist_ok=True)

    @staticmethod
    def peek(usb_root: str, name: str) -> dict:
        """Read the saved pcinfo without creating the folder."""
        return _read_pcinfo(os.path.join(usb_root, name)) or {}

    def path(self, sub: str, *names: str) -> str:
        return os.path.join(self.base, sub, *names)

    # PC info (system name, purpose, asset no., exceptions)
    def load_pcinfo(self) -> dict:
        p = self.path("data", "pcinfo.json")
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, ValueError):
                pass
        return {"system_name": "", "purpose": "", "asset_no": "", "exceptions": {}}

    def save_pcinfo(self, info: dict) -> None:
        p = self.path("data", "pcinfo.json")
        with open(p + ".tmp", "w", encoding="utf-8") as f:
            json.dump(info, f, ensure_ascii=False, indent=2)
        os.replace(p + ".tmp", p)

    def new_backup_dir(self) -> str:
        d = self.path("backup", time.strftime("%Y%m%d_%H%M%S"))
        os.makedirs(d, exist_ok=True)
        return d

    def latest_backup_dir(self) -> str:
        root = self.path("backup")
        dirs = sorted(d for d in os.listdir(root)
                      if not d.endswith(_RESTORED) and os.path.exists(os.path.join(root, d, "journal.json")))
        return os.path.join(root, dirs[-1]) if dirs else ""

    def clean_tmp(self) -> None:
        shutil.rmtree(self.path("tmp"), ignore_errors=True)
        os.makedirs(self.path("tmp"), exist_ok=True)

    # unfinished-work marker (reported on the next run if, e.g., the USB was pulled)
    def mark_running(self, what: str) -> None:
        with open(self.path("data", "running.json"), "w", encoding="utf-8") as f:
            json.dump({"what": what, "at": time.strftime("%Y-%m-%d %H:%M:%S")}, f, ensure_ascii=False)

    def clear_running(self) -> None:
        try:
            os.remove(self.path("data", "running.json"))
        except OSError:
            pass

    def unfinished(self) -> dict | None:
        p = self.path("data", "running.json")
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, ValueError):
                return {"what": "unknown", "at": ""}
        return None
