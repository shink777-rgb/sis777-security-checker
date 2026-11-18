"""Word checklist — fill the {{placeholders}} in templates/form_2026.docx and write a new .docx (standard library only).

The form is the Korean official checklist, so all filled-in values stay Korean.
"""
from __future__ import annotations

import os
import re
import zipfile
from xml.sax.saxutils import escape

from ..core.usbguard import program_dir

TEMPLATE = os.path.join(program_dir(), "templates", "form_2026.docx")
CODES = [f"PC-{i:02d}" for i in range(1, 23)]
EV_CODES = [c for c in CODES if c != "PC-20"]          # PC-20 (CMOS) stays blank in the evidence appendix
REQUIRED = (["SYS_NAME", "PURPOSE", "ASSET_NO", "MAC", "TYPE_NEW", "TYPE_REG", "TYPE_ADHOC", "DATE", "EXCEPTIONS",
             "FOLDER", "EB_PC00", "EN_PC00"]
            + [f"R_{c.replace('-', '')}" for c in CODES] + [f"N_{c.replace('-', '')}" for c in CODES]
            + [f"{p}_{c.replace('-', '')}" for c in EV_CODES for p in ("EB", "EA", "EN")])
PH = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def template_available(path: str = TEMPLATE) -> bool:
    """The checklist form is not distributed with the source; without it the Word checklist is skipped."""
    return os.path.isfile(path)


def template_check(path: str = TEMPLATE) -> list[str]:
    """Placeholders missing from the template (checked at start-up)."""
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    found = set(PH.findall(xml))
    return [p for p in REQUIRED if p not in found]


def values(results, meta: dict) -> dict[str, str]:
    info, typ = meta["pcinfo"], meta["type"]
    v = {"SYS_NAME": info.get("system_name", ""), "PURPOSE": info.get("purpose", ""),
         "ASSET_NO": info.get("asset_no", ""), "MAC": info.get("mac", ""), "DATE": meta["date"],
         "TYPE_NEW": "■" if typ == "신규" else "□", "TYPE_REG": "■" if typ == "정기" else "□",
         "TYPE_ADHOC": "■" if typ == "수시" else "□"}
    by = {r.code: r for r in results}
    for c in CODES:
        r = by.get(c)
        k = c.replace("-", "")
        v[f"R_{k}"] = r.mark if r else ""
        note = ""
        if r:
            if r.status.value in ("해당 없음", "점검 오류"):
                note = r.status.value
            elif r.note:
                note = r.note
            elif r.status.value == "부분 설정":
                note = r.current
            if r.managed:
                note = (note + " / " if note else "") + r.managed
        v[f"N_{k}"] = note[:60]
    v.update(evidence_values(meta))
    exc = meta.get("exceptions", {})
    v["EXCEPTIONS"] = "; ".join(f"{c}: {e.get('reason', '')}(보완: {e.get('measure', '')})" for c, e in exc.items()) or "없음"
    return v


def evidence_values(meta: dict) -> dict[str, str]:
    """Values for the evidence appendix. "After" evidence exists only for auto-fixed items."""
    ev = meta.get("evidence") or {}
    on = meta.get("evidence_enabled", True)
    v = {"FOLDER": meta.get("folder", "")}
    for c in ["PC-00"] + EV_CODES:
        k = c.replace("-", "")
        e = ev.get(c, {})
        v[f"EB_{k}"] = e.get("before", "") or ("" if on else "캡쳐 안 함")
        notes = list(e.get("note", []))
        if c != "PC-00":
            v[f"EA_{k}"] = e.get("after", "") or ("-" if e.get("before") else "")
        if not on:
            notes = notes or ["증빙 캡쳐 꺼짐"]
        v[f"EN_{k}"] = ", ".join(dict.fromkeys(notes))
    return v


def write(path: str, results, meta: dict, template: str = TEMPLATE) -> str:
    vals = values(results, meta)
    with zipfile.ZipFile(template) as zin, zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "word/document.xml":
                xml = data.decode("utf-8")
                xml = PH.sub(lambda m: escape(vals.get(m.group(1), "")), xml)
                data = xml.encode("utf-8")
            zout.writestr(item, data)
    return path
