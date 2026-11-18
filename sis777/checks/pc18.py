from .base import Check, FixStepMixin, Status, policy_managed, reg

POL = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
SYS = r"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance"


class PC18(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-18", "원격 지원을 금지하도록 정책을 설정", "4. 보안 관리", "중", True
    guide = "gpedit > 관리 템플릿 > 시스템 > 원격 지원 > '원격 지원 제공' 사용 안 함."

    def check(self, ctx):
        pol, sysv = reg.val(POL, "fAllowToGetHelp"), reg.val(SYS, "fAllowToGetHelp")
        eff = pol if pol is not None else sysv
        r = self.new(expected="원격 지원 사용 안 함(fAllowToGetHelp = 0)",
                     current="사용" if eff == 1 else "사용 안 함",
                     evidence=[reg.show(POL, "fAllowToGetHelp") + " (정책, 우선)", reg.show(SYS, "fAllowToGetHelp")])
        r.status = Status.VULN if eff == 1 else Status.GOOD
        if eff == 1:
            r.managed = policy_managed(ctx, pol is not None)
            self.step(r, "원격 지원 제공(fAllowToGetHelp)", 1, 0)
        return r

    def fix(self, ctx, result, journal, keys=None):
        journal.set_reg(self.code, POL, "fAllowToGetHelp", 0, reg.REG_DWORD)
        journal.set_reg(self.code, SYS, "fAllowToGetHelp", 0, reg.REG_DWORD)
        return "원격 지원 사용 안 함"
