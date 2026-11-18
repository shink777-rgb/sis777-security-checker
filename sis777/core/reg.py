"""Registry read/write (always the 64-bit view).

Paths look like 'HKLM\\SOFTWARE\\...'. 'HKCU\\...' is mapped to the signed-in user's hive (HKU\\<SID>),
because after elevation HKCU may point to the administrator account instead.
"""
from __future__ import annotations

try:
    import winreg  # type: ignore
except ImportError:  # not Windows (unit tests)
    winreg = None

REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 4, 7, 11
TYPE_NAME = {1: "REG_SZ", 2: "REG_EXPAND_SZ", 4: "REG_DWORD", 7: "REG_MULTI_SZ", 11: "REG_QWORD"}

_user_sid: str | None = None


def set_user_sid(sid: str | None) -> None:
    global _user_sid
    _user_sid = sid


def _split(path: str):
    if winreg is None:
        raise OSError("winreg not available (Windows only)")
    hive, _, sub = path.partition("\\")
    hive = hive.upper()
    if hive in ("HKCU", "HKEY_CURRENT_USER"):
        if _user_sid:
            return winreg.HKEY_USERS, f"{_user_sid}\\{sub}"
        return winreg.HKEY_CURRENT_USER, sub
    table = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKU": winreg.HKEY_USERS, "HKEY_USERS": winreg.HKEY_USERS,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
    }
    return table[hive], sub


def resolved(path: str) -> str:
    """Human-readable path (HKCU resolved to HKU\\SID)."""
    hive, _, sub = path.partition("\\")
    if hive.upper() == "HKCU" and _user_sid:
        return f"HKU\\{_user_sid}\\{sub}"
    return path


def get(path: str, name: str, wow32: bool = False):
    """(value, type) if the value exists, otherwise None."""
    try:
        root, sub = _split(path)
        view = winreg.KEY_WOW64_32KEY if wow32 else winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ | view) as k:
            return winreg.QueryValueEx(k, name)
    except (FileNotFoundError, OSError):
        return None


def val(path: str, name: str, default=None):
    r = get(path, name)
    return default if r is None else r[0]


def exists(path: str) -> bool:
    try:
        root, sub = _split(path)
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except OSError:
        return False


def set_value(path: str, name: str, value, typ: int) -> None:
    root, sub = _split(path)
    with winreg.CreateKeyEx(root, sub, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
        winreg.SetValueEx(k, name, 0, typ, value)


def delete_value(path: str, name: str) -> None:
    root, sub = _split(path)
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
            winreg.DeleteValue(k, name)
    except FileNotFoundError:
        pass


def subkeys(path: str, wow32: bool = False) -> list[str]:
    out = []
    try:
        root, sub = _split(path)
        view = winreg.KEY_WOW64_32KEY if wow32 else winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ | view) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def show(path: str, name: str) -> str:
    """'path\\name = value' string for evidence (Korean, as it appears in the reports)."""
    r = get(path, name)
    v = "(값 없음)" if r is None else repr(r[0])
    return f"{resolved(path)}\\{name} = {v}"
