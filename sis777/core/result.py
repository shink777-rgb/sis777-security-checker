"""Result data structures and scoring.

Status values and severities (상/중/하 = high/medium/low) stay Korean: they are printed on the Korean checklist.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    GOOD = "양호"
    PARTIAL = "부분 설정"
    VULN = "취약"
    MANUAL = "수동 확인"
    EXCEPT = "예외"
    NA = "해당 없음"
    ERROR = "점검 오류"


# Marks used on the official checklist form
MARK = {
    Status.GOOD: "〇",
    Status.PARTIAL: "△",
    Status.VULN: "X",
    Status.EXCEPT: "X",
    Status.NA: "〇",
    Status.MANUAL: "",
    Status.ERROR: "",
}

WEIGHT = {"상": 3, "중": 2, "하": 1}


@dataclass
class FixStep:
    """One planned change (shown in P-04 as current → new)."""
    desc: str
    before: str
    after: str
    risky: bool = False          # asked again in P-05
    irreversible: bool = False   # cannot be restored (e.g. removing app packages)
    key: str = ""                # item-internal key (service name, etc.)


@dataclass
class Result:
    code: str
    title: str
    category: str
    severity: str
    status: Status = Status.ERROR
    current: str = ""
    expected: str = ""
    evidence: list[str] = field(default_factory=list)
    guide: str = ""
    note: str = ""
    fixable: bool = False
    fix_plan: list[FixStep] = field(default_factory=list)
    managed: str = ""            # e.g. managed by Group Policy / a security product → excluded from auto-fix
    needs_reboot: bool = False
    needs_relogon: bool = False

    @property
    def mark(self) -> str:
        return MARK[self.status]

    @property
    def auto_fixable(self) -> bool:
        return (self.fixable and not self.managed and bool(self.fix_plan)
                and self.status in (Status.VULN, Status.PARTIAL))

    def to_dict(self) -> dict:
        return {
            "code": self.code, "title": self.title, "category": self.category,
            "severity": self.severity, "status": self.status.value, "mark": self.mark,
            "current": self.current, "expected": self.expected,
            "evidence": self.evidence, "guide": self.guide, "note": self.note,
            "managed": self.managed,
        }


def score(results: list[Result]) -> tuple[int | None, dict]:
    """Weighted score (0-100). N/A, check errors and unanswered manual items are left out of the denominator."""
    total = got = 0.0
    counts: dict[str, int] = {s.value: 0 for s in Status}
    for r in results:
        counts[r.status.value] += 1
        w = WEIGHT.get(r.severity, 1)
        if r.status in (Status.NA, Status.ERROR, Status.MANUAL):
            continue
        total += w
        if r.status == Status.GOOD:
            got += w
        elif r.status == Status.PARTIAL:
            got += w / 2
    if total == 0:
        return None, counts
    return round(got / total * 100), counts
