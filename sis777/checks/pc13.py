from .av import av_products, defender, is_defender
from .base import Check, Status


class PC13(Check):
    code, title, category, severity = "PC-13", "바이러스 백신 프로그램 설치 및 주기적 업데이트", "4. 보안 관리", "상"
    guide = "백신 설치 후 엔진(서명) 업데이트를 7일 이내로 유지(자동 업데이트 설정). 폐쇄망은 업데이트 서버 확인."

    def check(self, ctx):
        days = ctx.cfg["antivirus"]["signature_max_days"]
        prods = av_products(ctx)
        d = defender(ctx)
        r = self.new(expected=f"백신 설치, 서명 업데이트 {days}일 이내",
                     evidence=[f"{p['name']} productState=0x{p['state']:06X} (실시간 {'켜짐' if p['on'] else '꺼짐'}, "
                               f"서명 {'최신' if p['fresh'] else '오래됨'})" for p in prods])
        if d:
            r.evidence.append(f"Defender 서명 {d.get('SigDate')} ({d.get('AntivirusSignatureAge')}일 경과)")
        if not prods:
            r.status, r.current = Status.VULN, "등록된 백신 없음"
            return r
        active = [p for p in prods if p["on"]] or prods
        fresh = []
        for p in active:
            if is_defender(p["name"]) and d and d.get("AntivirusSignatureAge") is not None:
                ok = int(d["AntivirusSignatureAge"]) <= days
            else:
                ok = p["fresh"]
            fresh.append((p["name"], ok))
        r.current = ", ".join(f"{n}(서명 {'최신' if ok else '기준 초과'})" for n, ok in fresh)
        r.status = Status.GOOD if any(ok for _, ok in fresh) else Status.PARTIAL
        return r
