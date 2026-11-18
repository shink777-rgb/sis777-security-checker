from .base import Check, Status, contains_any, installed_programs, processes, reg


def find_messengers(programs: list[dict], procs: set[str], block: list[dict], allow: list[str]) -> list[str]:
    found = []
    for m in block:
        if contains_any(m["name"], allow):
            continue
        hit = next((p["name"] for p in programs if contains_any(p["name"], m.get("display", []))), "")
        run = next((x for x in m.get("process", []) if x.lower() in procs), "")
        if hit or run:
            found.append(f"{m['name']}" + (" (실행 중)" if run else ""))
    return found


class PC06(Check):
    code, title, category, severity = "PC-06", "비인가 상용 메신저 사용 금지", "2. 서비스 관리", "상"
    guide = "제어판 > 프로그램 및 기능에서 비인가 상용 메신저 삭제. 인가 메신저는 criteria.json의 messenger.allowlist에 등록."

    def check(self, ctx):
        c = ctx.cfg["messenger"]
        found = find_messengers(installed_programs(ctx), processes(ctx), c["blocklist"], c.get("allowlist", []))
        pol = r"HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client"
        r = self.new(expected="비인가 상용 메신저 미설치·미실행",
                     current=", ".join(found) if found else "발견 안 됨",
                     evidence=[reg.show(pol, "PreventRun") + " (Windows Messenger, 참고)",
                               f"인가 예외 목록: {', '.join(c.get('allowlist', [])) or '없음'}"])
        r.status = Status.VULN if found else Status.GOOD
        return r
