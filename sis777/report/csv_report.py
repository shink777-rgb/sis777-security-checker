import csv

_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def safe(v) -> str:
    """Prefix values starting with = + - @ etc. with ' so Excel does not run them as formulas."""
    s = "" if v is None else str(v)
    return "'" + s if s.startswith(_FORMULA) else s


def write(path: str, results, meta: dict) -> str:
    pc, info = meta["pc"], meta["pcinfo"]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["코드", "항목", "분류", "중요도", "결과", "표기", "현재값", "기준값", "비고",
                    "점검일시", "컴퓨터명", "MAC 주소", "시스템명", "점검구분"])
        for r in results:
            w.writerow([safe(x) for x in [r.code, r.title, r.category, r.severity, r.status.value, r.mark, r.current, r.expected,
                        r.note, meta["datetime"], pc.computer, info.get("mac", ""), info.get("system_name", ""), meta["type"]]])
    return path
