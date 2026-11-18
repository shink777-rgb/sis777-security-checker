from .base import Check, FixStepMixin, Status, run_ps
from ..core.ps import ps_quote


class PC22(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-22", "Xbox Game Bar 삭제 여부", "5. 추가 점검 항목", "상", True
    guide = "PowerShell(관리자): Remove-AppxPackage -AllUsers, Remove-AppxProvisionedPackage -Online (xbox 포함 패키지)."

    def check(self, ctx):
        inst = run_ps("Get-AppxPackage -AllUsers | Where-Object Name -match 'xbox' | Select-Object Name, PackageFullName", 60)
        prov = run_ps("Get-AppxProvisionedPackage -Online | Where-Object DisplayName -match 'xbox' | Select-Object DisplayName, PackageName", 60)
        r = self.new(expected="xbox 패키지(설치·프로비저닝) 없음",
                     current=f"설치 {len(inst)}개, 프로비저닝 {len(prov)}개",
                     evidence=[x["PackageFullName"] for x in inst] + [x["PackageName"] for x in prov])
        if not inst and not prov:
            r.status = Status.GOOD
            if ctx.pc.edition_id in ("EnterpriseS", "IoTEnterpriseS"):
                r.note = "LTSC 기본 구성(Xbox 앱 미포함)"
        elif inst and prov:
            r.status = Status.VULN
        else:
            r.status = Status.PARTIAL
        if inst or prov:
            self.step(r, "Xbox 앱 패키지 삭제", f"{len(inst) + len(prov)}개", "삭제(원복 불가, Store에서 재설치)",
                      irreversible=True)
        ctx.cache["pc22"] = (inst, prov)
        return r

    def fix(self, ctx, result, journal, keys=None):
        inst, prov = ctx.cache.get("pc22", ([], []))
        lines = [f"Remove-AppxPackage -AllUsers -Package {ps_quote(x['PackageFullName'])} -ErrorAction SilentlyContinue" for x in inst]
        lines += [f"Remove-AppxProvisionedPackage -Online -AllUsers -PackageName {ps_quote(x['PackageName'])} -ErrorAction SilentlyContinue | Out-Null"
                  for x in prov]
        if lines:
            journal.irreversible(self.code, "Xbox 패키지 삭제", ";".join(lines))
        return f"Xbox 패키지 {len(lines)}개 삭제"
