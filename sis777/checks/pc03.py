from .base import Check, FixStepMixin, Status, reg

KEY = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"


class PC03(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-03", "복구 콘솔에서 자동 로그온을 금지하도록 설정하여 사용", "1. 계정 관리", "중", True
    guide = "로컬 보안 정책 > 보안 옵션: '복구 콘솔: 자동 관리 로그온 허용' 사용 안 함."

    def check(self, ctx):
        v = reg.val(KEY, "SecurityLevel")
        r = self.new(expected="사용 안 함(SecurityLevel 0 또는 값 없음)",
                     current="사용" if v == 1 else "사용 안 함", evidence=[reg.show(KEY, "SecurityLevel")])
        r.status = Status.VULN if v == 1 else Status.GOOD
        if v == 1:
            self.step(r, "복구 콘솔 자동 관리 로그온", "1(사용)", "0(사용 안 함)")
        return r

    def fix(self, ctx, result, journal, keys=None):
        journal.set_reg(self.code, KEY, "SecurityLevel", 0, reg.REG_DWORD)
        return "SecurityLevel = 0"
