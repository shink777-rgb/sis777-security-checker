from .base import Check, FixStepMixin, Status, run_ps, services


def judge(rows: dict[str, dict], targets: list[str]) -> tuple[Status, list[str], list[str]]:
    """Judge only the target services that exist. (states, compliant, violating)"""
    ok, bad = [], []
    for name in targets:
        s = rows.get(name.lower())
        if not s:
            continue
        if s.get("State") == "Stopped" and s.get("StartMode") == "Disabled":
            ok.append(s["Name"])
        else:
            bad.append(s["Name"])
    if not ok and not bad:
        return Status.NA, ok, bad
    if not bad:
        return Status.GOOD, ok, bad
    return (Status.VULN if not ok else Status.PARTIAL), ok, bad


def has_physical_printer() -> bool:
    rows = run_ps("Get-CimInstance Win32_Printer | Select-Object Name, DriverName, PortName")
    virtual = ("pdf", "xps", "onenote", "fax", "팩스")
    for p in rows:
        txt = f"{p.get('Name', '')} {p.get('DriverName', '')} {p.get('PortName', '')}".lower()
        if not any(v in txt for v in virtual) and not str(p.get("PortName", "")).upper().startswith(("PORTPROMPT", "NUL", "FILE")):
            return True
    return False


class PC05(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-05", "항목의 불필요한 서비스 제거", "2. 서비스 관리", "상", True
    guide = "services.msc에서 불필요한 서비스 중지, 시작 유형 '사용 안 함'. Windows Update·DHCP Client는 제외."

    def check(self, ctx):
        targets = list(ctx.cfg["services"]["targets"])
        excluded = []
        if "spooler" in [t.lower() for t in targets] and has_physical_printer():
            targets = [t for t in targets if t.lower() != "spooler"]
            excluded.append("Spooler(프린터 연결됨)")
        rows = services(ctx)
        st, ok, bad = judge(rows, targets)
        r = self.new(status=st, expected="대상 서비스 중지 + 시작 유형 '사용 안 함'",
                     current=f"준수 {len(ok)}개, 실행·자동 {len(bad)}개" + (f" ({', '.join(bad)})" if bad else ""))
        r.evidence = [f"{rows[n.lower()]['Name']}: {rows[n.lower()]['State']} / {rows[n.lower()]['StartMode']}"
                      for n in targets if n.lower() in rows]
        if excluded:
            r.note = "제외: " + ", ".join(excluded)
        for n in bad:
            s = rows[n.lower()]
            self.step(r, f"서비스 {n} ({s.get('DisplayName', '')})", f"{s['State']}/{s['StartMode']}",
                      "Stopped/Disabled", key=n, risky=True)
        return r

    def fix(self, ctx, result, journal, keys=None):
        done = []
        for st in result.fix_plan:
            if keys is not None and st.key not in keys:
                continue
            journal.set_service(self.code, st.key)
            done.append(st.key)
        ctx.cache.pop("services", None)
        return "서비스 중지: " + ", ".join(done)
