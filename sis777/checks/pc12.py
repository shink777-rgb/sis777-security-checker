from .base import Check, FixStepMixin, Status, reg

KEY = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


class PC12(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-12", "Windows 자동 로그인 점검", "4. 보안 관리", "중", True
    guide = "레지스트리 Winlogon\\AutoAdminLogon = \"0\", DefaultPassword(평문 암호) 삭제."

    def check(self, ctx):
        auto = str(reg.val(KEY, "AutoAdminLogon", "") or "")
        pw = reg.get(KEY, "DefaultPassword") is not None
        r = self.new(expected="AutoAdminLogon이 \"1\"이 아니고 DefaultPassword 없음",
                     current=f"자동 로그인 {'사용' if auto == '1' else '사용 안 함'}" + (", 평문 암호 저장됨" if pw else ""),
                     evidence=[reg.show(KEY, "AutoAdminLogon"), f"{KEY}\\DefaultPassword {'있음' if pw else '없음'}(값은 표시 안 함)"])
        r.status = Status.VULN if (auto == "1" or pw) else Status.GOOD
        if auto == "1":
            self.step(r, "AutoAdminLogon", "\"1\"", "\"0\"", key="auto")
        if pw:
            self.step(r, "DefaultPassword(평문 암호)", "있음", "삭제(원복 불가)", key="pw", irreversible=True)
        return r

    def fix(self, ctx, result, journal, keys=None):
        sel = {s.key for s in result.fix_plan if keys is None or s.key in keys}
        if "auto" in sel:
            journal.set_reg(self.code, KEY, "AutoAdminLogon", "0", reg.REG_SZ)
        if "pw" in sel:
            journal.del_reg(self.code, KEY, "DefaultPassword", secret=True)
        return "자동 로그인 해제"
