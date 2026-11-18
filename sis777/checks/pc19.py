from .base import Check, Status, contains_any, installed_programs, services

PRIORITY = ["safe", "usb", "매체", "media", "device", "디바이스", "보안"]


def candidates(programs: list[dict], svcs: dict[str, dict]) -> dict:
    """Candidate lists for the P-11 pop-up (USB/media related entries first)."""
    def rank(name: str) -> tuple[int, str]:
        hit = contains_any(name, PRIORITY)
        return (PRIORITY.index(hit) if hit else len(PRIORITY), name.lower())
    progs = sorted({p["name"] for p in programs}, key=rank)
    sv = sorted((f"{s['Name']} | {s.get('DisplayName', '')}" for s in svcs.values()), key=rank)
    return {"programs": progs, "services": sv}


class PC19(Check):
    code, title, category, severity = "PC-19", "SafeUSB 설치", "5. 추가 점검 항목", "상"
    guide = "외부 저장매체 보호를 위해 SafeUSB 설치 및 서비스 실행 유지."

    def _find(self, ctx):
        cfg = ctx.cfg["safeusb"]
        prog = next((p["name"] for p in installed_programs(ctx) if contains_any(p["name"], cfg["product_names"])), "")
        svc = next((s for s in services(ctx).values()
                    if contains_any(s["Name"], cfg["service_names"]) or contains_any(s.get("DisplayName", ""), cfg["service_names"])), None)
        return prog, svc

    def check(self, ctx):
        cfg = ctx.cfg["safeusb"]
        prog, svc = self._find(ctx)
        if not prog and not svc:
            ans = ctx.ask("P-11", candidates(installed_programs(ctx), services(ctx)))
            if ans is None:
                return self.new(status=Status.MANUAL, expected="SafeUSB 설치 및 서비스 실행",
                                current="판정 보류(SafeUSB 선택을 나중으로 미룸)")
            if ans and not ans.get("not_installed"):
                if ans.get("product") and ans["product"] not in cfg["product_names"]:
                    cfg["product_names"].append(ans["product"])
                if ans.get("service") and ans["service"] not in cfg["service_names"]:
                    cfg["service_names"].append(ans["service"])
                ctx.cfg_dirty = True
                prog, svc = self._find(ctx)
        r = self.new(expected="SafeUSB 설치 및 서비스 실행",
                     evidence=[f"등록된 제품명: {', '.join(cfg['product_names']) or '없음'}",
                               f"등록된 서비스명: {', '.join(cfg['service_names']) or '없음'}"])
        if not prog and not svc:
            r.status, r.current = Status.VULN, "설치되어 있지 않음"
            return r
        running = svc is not None and svc.get("State") == "Running"
        r.current = f"제품: {prog or '확인 안 됨'} / 서비스: {svc['Name'] + ' ' + svc['State'] if svc else '확인 안 됨'}"
        # with a registered service name it must be running to be good; product found but service stopped = partial
        r.status = Status.PARTIAL if (svc is not None and not running) else Status.GOOD
        return r
