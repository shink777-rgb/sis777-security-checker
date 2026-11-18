from .av import av_products, defender
from .base import Check, Status


class PC14(Check):
    code, title, category, severity = "PC-14", "바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화", "4. 보안 관리", "상"
    guide = "백신 환경 설정에서 실시간 감시 사용. 다른 회사 백신은 해당 프로그램에서 설정."

    def check(self, ctx):
        prods = av_products(ctx)
        d = defender(ctx)
        on = [p["name"] for p in prods if p["on"]]
        r = self.new(expected="설치된 백신의 실시간 감시 켜짐",
                     current=("켜짐: " + ", ".join(on)) if on else ("백신 없음" if not prods else "실시간 감시 꺼짐"),
                     evidence=[f"{p['name']}: {'켜짐' if p['on'] else '꺼짐'}" for p in prods])
        if d:
            r.evidence.append(f"Defender RealTimeProtectionEnabled={d.get('RealTimeProtectionEnabled')}, "
                              f"변조 방지={d.get('IsTamperProtected')}")
        r.status = Status.GOOD if on else Status.VULN
        return r
