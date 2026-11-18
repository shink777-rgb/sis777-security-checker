from .base import Check, FixStepMixin, Status, run_ps, secpol


class PC01(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-01", "비밀번호의 주기적 변경(최대 암호사용기간 90일)", "1. 계정 관리", "상", True
    guide = "로컬 보안 정책 > 계정 정책 > 암호 정책: 최대 암호 사용 기간 90일, 최소 1일, 최근 암호 기억 24개. 계정 속성의 '암호 사용 기간 제한 없음' 해제."

    def check(self, ctx):
        c = ctx.cfg["password"]
        sp = secpol(ctx)
        max_age = sp.get("MaximumPasswordAge", -1)
        r = self.new(expected=f"최대 암호 사용 기간 1~{c['max_age_days']}일, 활성 계정의 '기간 제한 없음' 해제")
        users = run_ps("Get-LocalUser | Where-Object Enabled | Select-Object Name, "
                       "@{n='NoExpire';e={$null -eq $_.PasswordExpires -and $_.PasswordRequired}}")
        never = [u["Name"] for u in users if u.get("NoExpire")]
        age_ok = isinstance(max_age, int) and 0 < max_age <= c["max_age_days"]
        r.current = f"최대 암호 사용 기간: {'제한 없음' if max_age in (-1, 0) else str(max_age) + '일'}"
        if never:
            r.current += f", 기간 제한 없는 계정: {', '.join(never)}"
        r.evidence = [f"secedit [System Access] MaximumPasswordAge = {max_age}",
                      f"MinimumPasswordAge = {sp.get('MinimumPasswordAge')}, PasswordHistorySize = {sp.get('PasswordHistorySize')}"]
        if ctx.pc.domain_joined:
            r.note = "도메인 계정은 도메인 정책을 따름(로컬 정책 기준으로 판정)"
        if age_ok and not never:
            r.status = Status.GOOD
        elif age_ok:
            r.status = Status.PARTIAL
        else:
            r.status = Status.VULN
        new = {"MaximumPasswordAge": c["max_age_days"], "MinimumPasswordAge": c["min_age_days"],
               "PasswordHistorySize": c["history"]}
        if not age_ok or sp.get("MinimumPasswordAge", 0) < c["min_age_days"] or sp.get("PasswordHistorySize", 0) < c["history"]:
            self.step(r, "암호 정책(최대/최소 기간, 기억 개수)",
                      f"{max_age}/{sp.get('MinimumPasswordAge')}/{sp.get('PasswordHistorySize')}",
                      f"{c['max_age_days']}/{c['min_age_days']}/{c['history']}", key="policy")
        for u in never:
            self.step(r, f"계정 '{u}' 암호 사용 기간 제한 없음", "사용", "해제", key=f"user:{u}")
        ctx.cache["pc01_new"] = new
        return r

    def fix(self, ctx, result, journal, keys=None):
        sp = secpol(ctx)
        done = []
        for st in result.fix_plan:
            if keys is not None and st.key not in keys:
                continue
            if st.key == "policy":
                new = ctx.cache["pc01_new"]
                old = {k: sp.get(k) for k in new if sp.get(k) is not None}
                journal.secedit(self.code, old, new, ctx.tmp)
                done.append("암호 정책")
            elif st.key.startswith("user:"):
                journal.local_user_never_expires(self.code, st.key[5:], True)
                done.append(st.key[5:])
        ctx.cache.pop("secpol", None)
        return "설정: " + ", ".join(done)
