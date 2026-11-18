from .base import Check, Status


class PC21(Check):
    code, title, category, severity = "PC-21", "내 PC 지키미를 매월 1회 실행하고 조치하고 있는가?", "5. 추가 점검 항목", "상"
    guide = "매월 1회 이상 이 프로그램으로 점검하고 취약 항목 조치."

    def check(self, ctx):
        days = ctx.cfg["monthly_check"]["max_days"]
        last = ctx.history.last_run_days_ago() if ctx.history else None
        r = self.new(expected=f"직전 점검이 {days}일 이내")
        if last is None:
            r.status, r.current = Status.PARTIAL, "이전 점검 기록 없음(이번 점검이 첫 기록)"
        else:
            r.current = f"직전 점검 {last}일 전"
            r.status = Status.GOOD if last <= days else Status.VULN
        r.evidence = ["USB의 <MAC>\\data\\history.db 점검 이력"]
        return r
