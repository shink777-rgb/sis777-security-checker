import re

from .base import Check, Status, run_cmd

GUID = re.compile(r"\{[0-9a-fA-F-]{36}\}")


def count_os_loaders(text: str) -> tuple[int, int]:
    """(OS loader count, recovery environment count) from 'bcdedit /enum osloader /v'. Sections are separated by blank lines."""
    os_n = re_n = 0
    for sect in re.split(r"\r?\n\s*\r?\n", text):
        if not GUID.search(sect):
            continue
        if re.search(r"^\s*winpe\s+(Yes|예)\s*$", sect, re.M | re.I):
            re_n += 1
        else:
            os_n += 1
    return os_n, re_n


class PC08(Check):
    code, title, category, severity = "PC-08", "대상 시스템이  Windows 서버를 제외한 다른 OS로 멀티 부팅이 가능하지 않도록 설정", "2. 서비스 관리", "중"
    guide = "불필요한 OS와 부팅 항목 제거(bcdedit /delete는 신중히, 백업 후 수동 진행)."

    def check(self, ctx):
        rc, out = run_cmd(["bcdedit", "/enum", "osloader", "/v"], 20)
        if rc != 0:
            raise RuntimeError(f"bcdedit 실행 실패: {out.strip()[:200]}")
        n, re_n = count_os_loaders(out)
        r = self.new(expected="PC 내 OS 1개", current=f"OS 부팅 항목 {n}개(복구 환경 {re_n}개 제외)",
                     evidence=[f"bcdedit /enum osloader: OS {n}, WinRE {re_n}"])
        r.status = Status.GOOD if n <= 1 else Status.VULN
        return r
