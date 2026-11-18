"""Shared by PC-13 and PC-14: Windows Security Center (SecurityCenter2) and Defender state."""
from .base import run_ps


def decode_state(state: int) -> tuple[bool, bool]:
    """productState → (real-time protection on, signatures up to date). Middle byte 0x10/0x11 = on, low byte 0x00 = up to date."""
    mid = (state >> 8) & 0xFF
    low = state & 0xFF
    return mid in (0x10, 0x11), low == 0x00


def av_products(ctx) -> list[dict]:
    if "av" not in ctx.cache:
        try:
            rows = run_ps("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |"
                          " Select-Object displayName, productState")
        except Exception:  # noqa: BLE001
            rows = []
        out = []
        for r in rows:
            on, fresh = decode_state(int(r.get("productState", 0)))
            out.append({"name": r.get("displayName", ""), "state": int(r.get("productState", 0)),
                        "on": on, "fresh": fresh})
        ctx.cache["av"] = out
    return ctx.cache["av"]


def defender(ctx) -> dict | None:
    if "def" not in ctx.cache:
        try:
            rows = run_ps("Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled,"
                          " AntivirusSignatureAge, IsTamperProtected,"
                          " @{n='SigDate';e={$_.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')}}")
            ctx.cache["def"] = rows[0] if rows else None
        except Exception:  # noqa: BLE001
            ctx.cache["def"] = None
    return ctx.cache["def"]


def is_defender(name: str) -> bool:
    n = name.lower()
    return "defender" in n or "windows 보안" in n
