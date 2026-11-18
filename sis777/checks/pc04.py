from .base import Check, FixStepMixin, Status, reg, run_ps

KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
ADMIN_TYPE = 2147483648      # administrative disk shares (C$, ADMIN$)


def classify(shares: list[dict], everyone: set[str]) -> tuple[list[str], list[str], list[str]]:
    """(default shares, user shares, shares granting Everyone) — IPC$ excluded."""
    admin = [s["Name"] for s in shares if int(s.get("Type", 0)) == ADMIN_TYPE]
    user = [s["Name"] for s in shares if int(s.get("Type", 0)) == 0]
    return admin, user, [n for n in user if n in everyone]


class PC04(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-04", "공유폴더 제거", "2. 서비스 관리", "상", True
    guide = "net share로 확인 후 불필요한 공유 삭제(net share 이름 /delete). 기본 공유 재생성 방지: AutoShareWks=0. 사용 중인 공유는 Everyone 권한 제거."

    def check(self, ctx):
        shares = run_ps("Get-CimInstance Win32_Share | Select-Object Name, Path, Type")
        every = run_ps(
            "$e=(New-Object Security.Principal.SecurityIdentifier('S-1-1-0')).Translate([Security.Principal.NTAccount]).Value;"
            "Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special } | ForEach-Object {"
            " $n=$_.Name; Get-SmbShareAccess -Name $n -ErrorAction SilentlyContinue |"
            " Where-Object { $_.AccountName -eq $e -and $_.AccessControlType -eq 'Allow' } | ForEach-Object { $n } }")
        admin, user, ev = classify(shares, set(every))
        wks = reg.val(KEY, "AutoShareWks")
        r = self.new(expected="기본 공유 없음, AutoShareWks = 0, 공유 폴더에 Everyone 권한 없음")
        r.current = f"기본 공유: {', '.join(admin) or '없음'} / 사용자 공유: {', '.join(user) or '없음'} / AutoShareWks: {wks}"
        r.evidence = [f"Win32_Share: {', '.join(s['Name'] for s in shares)}", reg.show(KEY, "AutoShareWks")]
        if ev:
            r.evidence.append(f"Everyone 권한 공유: {', '.join(ev)}")
        if admin or ev:
            r.status = Status.VULN
        elif wks != 0:
            r.status = Status.PARTIAL
            r.note = "기본 공유는 없으나 재부팅 시 다시 생성될 수 있음"
        else:
            r.status = Status.GOOD
        for n in admin:
            self.step(r, f"기본 공유 {n} 삭제", "공유 중", "삭제", key=f"share:{n}", risky=True)
        if wks != 0:
            self.step(r, "AutoShareWks / AutoShareServer", str(wks), "0", key="reg")
        if user:
            r.note = (r.note + " / " if r.note else "") + f"사용자 공유({', '.join(user)})는 직접 확인 후 정리"
        ctx.cache["pc04_paths"] = {s["Name"]: s.get("Path", "") for s in shares}
        return r

    def fix(self, ctx, result, journal, keys=None):
        done = []
        for st in result.fix_plan:
            if keys is not None and st.key not in keys:
                continue
            if st.key.startswith("share:"):
                n = st.key[6:]
                journal.share_delete(self.code, n, ctx.cache.get("pc04_paths", {}).get(n, ""))
                done.append(n)
            elif st.key == "reg":
                journal.set_reg(self.code, KEY, "AutoShareWks", 0, reg.REG_DWORD)
                journal.set_reg(self.code, KEY, "AutoShareServer", 0, reg.REG_DWORD)
                done.append("AutoShareWks=0")
                result.needs_reboot = True
        return "설정: " + ", ".join(done)
