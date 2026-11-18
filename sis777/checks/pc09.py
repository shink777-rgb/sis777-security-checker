from .base import Check, FixStepMixin, Status, policy_managed, reg

EDGE_LM = r"HKLM\SOFTWARE\Policies\Microsoft\Edge"
EDGE_CU = r"HKCU\Software\Policies\Microsoft\Edge"
IE = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache"
NAMES = ("ClearCachedImagesAndFilesOnExit", "ClearBrowsingDataOnExit")


class PC09(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-09", "브라우저 종료 시 임시 인터넷 파일 폴더의 내용을 삭제하도록 설정", "2. 서비스 관리", "하", True
    guide = "Edge 설정 > 개인 정보 > 브라우저를 닫을 때마다 지울 항목 > 캐시된 이미지 및 파일. (정책: ClearCachedImagesAndFilesOnExit=1)"

    def check(self, ctx):
        vals = {f"{k}\\{n}": reg.val(k, n) for k in (EDGE_LM, EDGE_CU) for n in NAMES}
        on = [k for k, v in vals.items() if v == 1]
        present = any(v is not None for v in vals.values())
        r = self.new(expected="Edge 종료 시 캐시 삭제 정책 = 1",
                     current="사용" if on else "사용 안 함",
                     evidence=[reg.show(EDGE_LM, n) for n in NAMES] + [reg.show(IE, "Persistent") + " (IE 참고)"])
        r.status = Status.GOOD if on else Status.VULN
        r.managed = policy_managed(ctx, present) if not on else ""
        if not on:
            self.step(r, "Edge ClearCachedImagesAndFilesOnExit", vals.get(f"{EDGE_LM}\\{NAMES[0]}"), 1)
        return r

    def fix(self, ctx, result, journal, keys=None):
        journal.set_reg(self.code, EDGE_LM, "ClearCachedImagesAndFilesOnExit", 1, reg.REG_DWORD)
        return "Edge 종료 시 캐시 삭제 정책 설정(Edge 재시작 후 적용)"
