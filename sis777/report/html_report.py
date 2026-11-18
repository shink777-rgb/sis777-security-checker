"""HTML report — single file, no external resources. Content is Korean (report for Korean users)."""
from html import escape

from .. import APP_NAME, APP_VERSION

COLOR = {"양호": "#2e7d32", "부분 설정": "#e67c00", "취약": "#c62828", "예외": "#6a1b9a",
         "수동 확인": "#e67c00", "해당 없음": "#777", "점검 오류": "#777"}


def write(path: str, results, meta: dict) -> str:
    pc, info, c = meta["pc"], meta["pcinfo"], meta["counts"]
    rows = []
    cat = None
    for r in results:
        if r.category != cat:
            cat = r.category
            rows.append(f"<tr class='cat'><td colspan='6'>{escape(cat)}</td></tr>")
        ev = "<br>".join(escape(e) for e in r.evidence)
        rows.append(
            f"<tr><td>{r.code}</td><td>{escape(r.title)}<div class='g'>{escape(r.guide)}</div></td><td class='c'>{r.severity}</td>"
            f"<td class='c' style='color:{COLOR.get(r.status.value, '#000')}'><b>{r.mark}</b> {r.status.value}</td>"
            f"<td>{escape(r.current)}<div class='g'>기준: {escape(r.expected)}</div>"
            f"{'<div class=n>' + escape(r.note) + '</div>' if r.note else ''}"
            f"{'<div class=n>' + escape(r.managed) + '</div>' if r.managed else ''}</td>"
            f"<td class='ev'>{ev}</td></tr>")
    html = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><title>{APP_NAME} 점검 결과</title>
<style>body{{font-family:'맑은 고딕',sans-serif;margin:24px;color:#222}}h1{{color:#1f3864;margin:0}}
.top{{color:#777;font-size:12px}}table{{border-collapse:collapse;width:100%;margin-top:12px;font-size:13px}}
td,th{{border:1px solid #bbb;padding:5px 7px;vertical-align:top}}th{{background:#d9e2f3}}.c{{text-align:center;white-space:nowrap}}
.cat td{{background:#f2f2f2;font-weight:bold}}.g{{color:#777;font-size:11px}}.n{{color:#8a5a00;font-size:11px}}
.ev{{font-family:Consolas,monospace;font-size:11px;color:#555;word-break:break-all}}
.box{{display:flex;gap:12px;margin-top:12px}}.k{{border:1px solid #ccc;padding:8px 14px;border-radius:6px}}.k b{{font-size:22px}}
@media print{{.ev{{display:none}}}}</style></head><body>
<div class="top">{APP_NAME} {APP_VERSION} | 개인용</div><h1>보안 점검 결과</h1>
<table><tr><th>시스템명</th><td>{escape(info.get('system_name', ''))}</td><th>용도</th><td>{escape(info.get('purpose', ''))}</td>
<th>관리번호</th><td>{escape(info.get('asset_no', ''))}</td></tr>
<tr><th>컴퓨터명</th><td>{escape(pc.computer)}</td><th>MAC 주소</th><td>{escape(info.get('mac', ''))}</td><th>IP</th><td>{escape(', '.join(pc.ips))}</td></tr>
<tr><th>OS</th><td>{escape(pc.os_label)} ({pc.build}.{pc.ubr})</td><th>점검구분</th><td>{escape(meta['type'])}</td><th>점검일시</th><td>{meta['datetime']}</td></tr></table>
<div class="box"><div class="k">점수<br><b>{meta['score'] if meta['score'] is not None else '-'}</b> (점검 전 {meta['score_before'] if meta['score_before'] is not None else '-'})</div>
<div class="k">양호 <b>{c['양호']}</b></div><div class="k">부분 <b>{c['부분 설정']}</b></div><div class="k">취약 <b>{c['취약']}</b></div>
<div class="k">예외 <b>{c['예외']}</b></div><div class="k">수동 확인 <b>{c['수동 확인']}</b></div><div class="k">해당 없음 <b>{c['해당 없음']}</b></div>
<div class="k">오류 <b>{c['점검 오류']}</b></div></div>
<table><tr><th>코드</th><th>항목</th><th>중요도</th><th>결과</th><th>현재값 / 기준</th><th>판정 근거</th></tr>{''.join(rows)}</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
