"""Helpers for running PowerShell and console commands.

- PowerShell output is returned as ConvertTo-Json and parsed (avoids locale-dependent text parsing).
- Scripts are passed with -EncodedCommand (UTF-16LE Base64), so there are no quoting problems on the command line.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess

CREATE_NO_WINDOW = 0x08000000


def _windows_dir() -> str:
    """Windows directory, read via the API because the SystemRoot environment variable can be changed by the user."""
    if os.name == "nt":
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buf, 260):
            return buf.value
    return r"C:\Windows"


SYSROOT = _windows_dir()
# A 32-bit process on 64-bit Windows sees SysWOW64 instead of System32 (no Get-LocalUser etc.), so use Sysnative
_SYSDIR = "Sysnative" if os.path.isdir(os.path.join(SYSROOT, "Sysnative")) else "System32"
SYS32 = os.path.join(SYSROOT, _SYSDIR)
PS_EXE = os.path.join(SYS32, "WindowsPowerShell", "v1.0", "powershell.exe")
MAX_CMDLINE = 32000   # a little below the Windows command-line limit (32767 characters)


def sysexe(name: str) -> str:
    """Full path of an executable in System32. A bare name could run a same-named file from the program folder (USB) first."""
    return os.path.join(SYS32, name if name.lower().endswith(".exe") else name + ".exe")


def encode_ps(body: str) -> str:
    """Value for -EncodedCommand (UTF-16LE Base64)."""
    return base64.b64encode(body.encode("utf-16-le")).decode("ascii")


class PSError(Exception):
    pass


def _flags() -> int:
    return CREATE_NO_WINDOW if os.name == "nt" else 0


def _decode(b: bytes) -> str:
    for enc in ("utf-8", "oem", "mbcs", "cp949"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return b.decode("utf-8", "replace")


def run_ps(script: str, timeout: int = 25, as_json: bool = True, env: dict | None = None):
    """Run a PowerShell script. With as_json=True the result is always a list."""
    prefix = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
              "[Console]::OutputEncoding=[Text.Encoding]::UTF8;")
    if as_json:
        body = (prefix + "$__r = & { " + script + " };"
                "if ($null -eq $__r) { 'null' } else { ConvertTo-Json -InputObject @($__r) -Depth 5 -Compress }")
    else:
        body = prefix + script
    enc = encode_ps(body)
    if len(enc) > MAX_CMDLINE - 200:
        raise PSError("PowerShell script too long (command-line limit)")
    full_env = None
    if env:
        full_env = dict(os.environ)
        full_env.update(env)
    try:
        p = subprocess.run(
            [PS_EXE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, creationflags=_flags(), env=full_env)
    except subprocess.TimeoutExpired as e:
        raise PSError(f"PowerShell timed out ({timeout} s)") from e
    except OSError as e:
        raise PSError(f"cannot start PowerShell: {e}") from e
    out = p.stdout.decode("utf-8", "replace").strip()
    if p.returncode != 0:
        err = _decode(p.stderr).strip()
        raise PSError(err[:400] or f"PowerShell exit code {p.returncode}")
    if not as_json:
        return out
    if not out or out == "null":
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def run_cmd(args: list[str], timeout: int = 25) -> tuple[int, str]:
    """Run a console command (output decoded with the OEM code page). Bare command names are resolved to System32."""
    if args and os.name == "nt" and not os.path.isabs(args[0]):
        args = [sysexe(args[0])] + list(args[1:])
    try:
        p = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, creationflags=_flags())
    except subprocess.TimeoutExpired:
        return -1, f"timed out ({timeout} s)"
    except OSError as e:
        return -1, str(e)
    return p.returncode, _decode(p.stdout) + _decode(p.stderr)


def language_mode() -> str:
    try:
        return run_ps("$ExecutionContext.SessionState.LanguageMode", as_json=False).strip()
    except PSError:
        return "Unknown"


# PowerShell treats ‘ ’ ‚ ‛ as single quotes too; if they are not doubled, input can break out of the string.
_SQ = "'\u2018\u2019\u201a\u201b"


def ps_quote(s: str) -> str:
    """PowerShell single-quoted string literal (all four quote characters doubled, NUL removed)."""
    out = []
    for ch in str(s).replace("\x00", ""):
        out.append(ch + ch if ch in _SQ else ch)
    return "'" + "".join(out) + "'"


def ps_regex(words) -> str:
    """Regex alternation (a|b|c) as a PowerShell literal; each word is regex-escaped."""
    import re
    return ps_quote("|".join(re.escape(w) for w in words if w))
