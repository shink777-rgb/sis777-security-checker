from .base import Check, Status


class PC20(Check):
    code, title, category, severity = "PC-20", "부팅패스워드(CMOS 패스워드) 설정 (9자리 이상)", "5. 추가 점검 항목", "상"
    guide = "BIOS/UEFI 설정에서 부팅(관리자) 패스워드 설정: 3종 조합 9자리 이상 또는 2종 조합 10자리 이상."

    def check(self, ctx):
        return self.new(status=Status.MANUAL, expected="3종 9자리 / 2종 10자리 이상 CMOS 패스워드",
                        current="자가점검 응답 필요(OS에서 확인 불가)")
