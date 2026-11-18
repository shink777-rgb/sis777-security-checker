import datetime as dt

from .base import Check, Status

CONSUMER = {"Core", "CoreN", "CoreSingleLanguage", "CoreCountrySpecific", "Professional", "ProfessionalN",
            "ProfessionalWorkstation", "ProfessionalWorkstationN"}
LTSC = {"EnterpriseS", "EnterpriseSN"}
IOT_LTSC = {"IoTEnterpriseS", "IoTEnterpriseSK"}


def edition_group(edition_id: str) -> str:
    if edition_id in IOT_LTSC:
        return "iot_ltsc"     # IoT Enterprise LTSC has longer support (e.g. LTSC 2021 → 2032)
    if edition_id in LTSC:
        return "ltsc"
    if edition_id in CONSUMER:
        return "consumer"
    return "enterprise"  # Enterprise, Education, ProfessionalEducation, ...


def lookup(table: list[dict], build: int, edition_id: str) -> dict | None:
    g = edition_group(edition_id)
    for row in table:
        if row["build"] == build and row["group"] == g:
            return row
    return None


class PC11(Check):
    code, title, category, severity = "PC-11", "지원이 종료되지 않은 Windows OS Build 적용", "3. 패치 관리", "상"
    guide = "지원 종료된 버전은 최신 기능 업데이트로 업그레이드. 지원표는 criteria.json의 os_support를 분기마다 갱신(Windows 10 ESU 가입 PC는 유료 연장 지원을 받으므로 별도 확인)."

    def check(self, ctx):
        pc = ctx.pc
        row = lookup(ctx.cfg["os_support"]["table"], pc.build, pc.edition_id)
        r = self.new(expected="에디션별 지원 종료일이 점검일 이후",
                     current=f"{pc.os_label} (빌드 {pc.build}.{pc.ubr}, EditionID {pc.edition_id})",
                     evidence=[f"CurrentBuild={pc.build}, UBR={pc.ubr}, EditionID={pc.edition_id}, 그룹={edition_group(pc.edition_id)}"])
        if not row:
            r.status = Status.MANUAL
            r.note = "지원표에 없는 빌드 — criteria.json os_support 갱신 필요"
            return r
        end = dt.date.fromisoformat(row["end"])
        r.evidence.append(f"지원표: {row['name']} ~ {row['end']} (지원표 확인일 {ctx.cfg['os_support'].get('checked', '-')})")
        r.status = Status.GOOD if dt.date.today() <= end else Status.VULN
        r.current += f", 지원 종료 {row['end']}"
        return r
