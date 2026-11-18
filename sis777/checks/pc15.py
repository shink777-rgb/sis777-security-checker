from .av import decode_state
from .base import Check, FixStepMixin, Status, policy_managed, reg, run_ps

POL = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"
POL_NAMES = {"Domain": "DomainProfile", "Private": "StandardProfile", "Public": "PublicProfile"}


class PC15(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-15", "OS에서 제공하는 침입차단 기능 활성화", "4. 보안 관리", "상", True
    guide = "제어판 > Windows Defender 방화벽 > 도메인·개인·공용 네트워크 모두 '사용'."

    def check(self, ctx):
        prof = run_ps("Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, @{n='On';e={[bool]$_.Enabled}}")
        try:
            third = run_ps("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct |"
                           " Select-Object displayName, productState")
        except Exception:  # noqa: BLE001
            third = []
        third_on = [t["displayName"] for t in third if decode_state(int(t.get("productState", 0)))[0]]
        on = [p["Name"] for p in prof if p.get("On")]
        off = [p["Name"] for p in prof if not p.get("On")]
        r = self.new(expected="도메인·개인·공용 프로필 모두 사용 또는 다른 회사 방화벽 사용",
                     current=f"사용: {', '.join(on) or '없음'} / 사용 안 함: {', '.join(off) or '없음'}"
                             + (f" / 다른 회사 방화벽: {', '.join(third_on)}" if third_on else ""),
                     evidence=[f"{p['Name']} Enabled={p.get('On')}" for p in prof])
        if not off or third_on:
            r.status = Status.GOOD
        elif on:
            r.status = Status.PARTIAL
        else:
            r.status = Status.VULN
        present = any(reg.val(f"{POL}\\{POL_NAMES[n]}", "EnableFirewall") is not None for n in off if n in POL_NAMES)
        if r.status != Status.GOOD:
            r.managed = policy_managed(ctx, present)
            for n in off:
                self.step(r, f"방화벽 {n} 프로필", "사용 안 함", "사용", key=n)
        return r

    def fix(self, ctx, result, journal, keys=None):
        done = []
        for st in result.fix_plan:
            if keys is None or st.key in keys:
                journal.firewall(self.code, st.key, False)
                done.append(st.key)
        return "방화벽 사용: " + ", ".join(done)
