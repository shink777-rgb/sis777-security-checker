import datetime as dt

from .base import Check, Status, reg, run_ps, services

WU_POL = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
AU_POL = WU_POL + r"\AU"


def latest_update_date() -> tuple[str, str]:
    """Install date (yyyy-MM-dd) of the latest update and the evidence. The date is formatted in PowerShell to avoid the JSON date format."""
    rows = run_ps(
        "$d=@();"
        "try { $s=New-Object -ComObject Microsoft.Update.Session; $h=$s.CreateUpdateSearcher(); $n=$h.GetTotalHistoryCount();"
        " if ($n -gt 0) { $h.QueryHistory(0,[Math]::Min($n,100)) | Where-Object { $_.Operation -eq 1 -and $_.ResultCode -eq 2 } |"
        " ForEach-Object { $d += [pscustomobject]@{D=$_.Date.ToLocalTime().ToString('yyyy-MM-dd'); S='WU 이력'} } } } catch {};"
        "Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | ForEach-Object {"
        " $d += [pscustomobject]@{D=$_.InstalledOn.ToString('yyyy-MM-dd'); S=('HotFix ' + $_.HotFixID)} };"
        "$d | Sort-Object D -Descending | Select-Object -First 1", timeout=60)
    if not rows:
        return "", ""
    return rows[0]["D"], rows[0]["S"]


def auto_update_state(ctx) -> tuple[bool, str]:
    no_auto = reg.val(AU_POL, "NoAutoUpdate")
    wsus = reg.val(WU_POL, "WUServer")
    wufb = reg.val(WU_POL, "DeferQualityUpdates") is not None or reg.val(WU_POL, "SetDisableUXWUAccess") is not None
    svc = services(ctx).get("wuauserv", {})
    if no_auto == 1:
        return False, "자동 업데이트 정책 사용 안 함(NoAutoUpdate=1)"
    if svc.get("StartMode") == "Disabled":
        return False, "Windows Update 서비스 사용 안 함"
    if wsus or wufb:
        return True, f"중앙 관리({'WSUS ' + str(wsus) if wsus else 'WUfB'})"
    return True, "자동 업데이트 사용"


class PC10(Check):
    code, title, category, severity = "PC-10", "주기적 보안 패치 및 벤더 권고사항 적용", "3. 패치 관리", "상"
    guide = "설정 > Windows 업데이트에서 최신 업데이트 설치, 자동 업데이트 유지. 내부 관리절차 수립·이행."

    def check(self, ctx):
        days = ctx.cfg["patch"]["max_days_since_install"]
        last, src = latest_update_date()
        auto_ok, auto_txt = auto_update_state(ctx)
        age = (dt.date.today() - dt.date.fromisoformat(last)).days if last else None
        recent = age is not None and age <= days
        r = self.new(expected=f"최근 업데이트 {days}일 이내, 자동 업데이트 사용",
                     current=f"최근 설치 {last or '기록 없음'}" + (f"({age}일 전)" if age is not None else "") + f", {auto_txt}",
                     evidence=[f"최근 설치: {last} [{src}]", reg.show(AU_POL, "NoAutoUpdate"), reg.show(WU_POL, "WUServer")])
        r.status = Status.GOOD if (recent and auto_ok) else Status.PARTIAL if (recent or auto_ok) else Status.VULN
        return r
