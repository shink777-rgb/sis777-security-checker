from .base import Check, FixStepMixin, Status, secpol


class PC02(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-02", "비밀번호 관리정책 설정", "1. 계정 관리", "상", True
    guide = "로컬 보안 정책 > 암호 정책: '암호는 복잡성을 만족해야 함' 사용, 최소 암호 길이 9자 이상."

    def check(self, ctx):
        need = ctx.cfg["password"]["min_length"]
        sp = secpol(ctx)
        cx, ln = sp.get("PasswordComplexity", 0), sp.get("MinimumPasswordLength", 0)
        r = self.new(expected=f"복잡성 사용, 최소 길이 {need}자 이상",
                     current=f"복잡성 {'사용' if cx == 1 else '사용 안 함'}, 최소 길이 {ln}자",
                     evidence=[f"PasswordComplexity = {cx}", f"MinimumPasswordLength = {ln}"])
        if cx == 1 and ln >= need:
            r.status = Status.GOOD
        elif cx == 1:
            r.status = Status.PARTIAL
        else:
            r.status = Status.VULN
        if r.status != Status.GOOD:
            self.step(r, "암호 복잡성/최소 길이", f"{cx}/{ln}", f"1/{max(ln, need)}", key="policy")
        return r

    def fix(self, ctx, result, journal, keys=None):
        need = ctx.cfg["password"]["min_length"]
        sp = secpol(ctx)
        new = {"PasswordComplexity": 1, "MinimumPasswordLength": max(sp.get("MinimumPasswordLength", 0), need)}
        old = {k: sp.get(k, 0) for k in new}
        journal.secedit(self.code, old, new, ctx.tmp)
        ctx.cache.pop("secpol", None)
        return "암호 복잡성·최소 길이 설정"
