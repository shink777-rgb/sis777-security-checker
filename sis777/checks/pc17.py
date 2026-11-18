from .base import Check, FixStepMixin, Status, policy_managed, reg

LM = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
CU = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
AP = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"


class PC17(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-17", "CD, DVD, USB 메모리 등과 같은 미디어의 자동실행 방지등 이동식 미디어에 대한 보안대책 수립", "4. 보안 관리", "상", True
    guide = "gpedit > 관리 템플릿 > Windows 구성 요소 > 자동 실행 정책 > '자동 실행 끄기: 모든 드라이브'. 이동식 매체 관리절차 수립."

    def check(self, ctx):
        lm, cu, dis = reg.val(LM, "NoDriveTypeAutoRun"), reg.val(CU, "NoDriveTypeAutoRun"), reg.val(AP, "DisableAutoplay")
        ok = lm == 255 or cu == 255 or dis == 1
        r = self.new(expected="NoDriveTypeAutoRun = 255(0xFF) 또는 DisableAutoplay = 1",
                     current="자동 실행 차단" if ok else "자동 실행 허용",
                     evidence=[reg.show(LM, "NoDriveTypeAutoRun"), reg.show(CU, "NoDriveTypeAutoRun"), reg.show(AP, "DisableAutoplay")])
        r.status = Status.GOOD if ok else Status.VULN
        if not ok:
            r.managed = policy_managed(ctx, lm is not None)
            self.step(r, "NoDriveTypeAutoRun(모든 드라이브)", "없음" if lm is None else hex(lm), "0xFF")
        return r

    def fix(self, ctx, result, journal, keys=None):
        journal.set_reg(self.code, LM, "NoDriveTypeAutoRun", 255, reg.REG_DWORD)
        return "모든 드라이브 자동 실행 차단"
