from .base import Check, FixStepMixin, Status, policy_managed, reg

DESK = r"HKCU\Control Panel\Desktop"
POL = r"HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
NAMES = ("ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut", "SCRNSAVE.EXE")
DEFAULT_SCR = r"C:\Windows\system32\scrnsave.scr"


def effective() -> tuple[dict, bool]:
    """A policy value wins over the user value. (value, policy present)"""
    out, pol = {}, False
    for n in NAMES:
        p = reg.val(POL, n)
        if p is not None:
            pol = True
            out[n] = p
        else:
            out[n] = reg.val(DESK, n)
    return out, pol


def judge(v: dict, max_sec: int) -> tuple[Status, list[str]]:
    active = str(v.get("ScreenSaveActive") or "0") == "1" and bool(v.get("SCRNSAVE.EXE"))
    secure = str(v.get("ScreenSaverIsSecure") or "0") == "1"
    try:
        t = int(v.get("ScreenSaveTimeOut") or 0)
    except ValueError:
        t = 0
    timeout_ok = 0 < t <= max_sec
    miss = [m for m, ok in (("화면보호기 사용", active), ("암호 보호", secure), (f"대기 {max_sec // 60}분 이하", timeout_ok)) if not ok]
    if not miss:
        return Status.GOOD, miss
    return (Status.VULN if not active else Status.PARTIAL), miss


class PC16(FixStepMixin, Check):
    code, title, category, severity, fixable = "PC-16", "화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설정", "4. 보안 관리", "상", True
    guide = "설정 > 개인 설정 > 잠금 화면 > 화면 보호기: 대기 10분 이하, '다시 시작할 때 로그온 화면 표시' 체크."

    def check(self, ctx):
        mx = ctx.cfg["screensaver"]["max_timeout_sec"]
        v, pol = effective()
        st, miss = judge(v, mx)
        r = self.new(status=st, expected=f"화면보호기 사용, 암호 보호, 대기 {mx // 60}분 이하",
                     current=f"사용={v.get('ScreenSaveActive')}, 암호={v.get('ScreenSaverIsSecure')}, "
                             f"대기={v.get('ScreenSaveTimeOut')}초, 화면보호기={v.get('SCRNSAVE.EXE') or '없음'}",
                     evidence=[reg.show(DESK, n) for n in NAMES] + ([f"정책 키 사용: {reg.resolved(POL)}"] if pol else []))
        if st != Status.GOOD:
            r.note = "미충족: " + ", ".join(miss)
            r.managed = policy_managed(ctx, pol)
            self.step(r, "화면보호기 설정(로그인 사용자)",
                      f"{v.get('ScreenSaveActive')}/{v.get('ScreenSaverIsSecure')}/{v.get('ScreenSaveTimeOut')}", f"1/1/{mx}")
        return r

    def fix(self, ctx, result, journal, keys=None):
        mx = ctx.cfg["screensaver"]["max_timeout_sec"]
        journal.set_reg(self.code, DESK, "ScreenSaveActive", "1", reg.REG_SZ)
        journal.set_reg(self.code, DESK, "ScreenSaverIsSecure", "1", reg.REG_SZ)
        try:
            t = int(reg.val(DESK, "ScreenSaveTimeOut") or 0)
        except ValueError:
            t = 0
        if not 0 < t <= mx:
            journal.set_reg(self.code, DESK, "ScreenSaveTimeOut", str(mx), reg.REG_SZ)
        if not reg.val(DESK, "SCRNSAVE.EXE"):
            journal.set_reg(self.code, DESK, "SCRNSAVE.EXE", DEFAULT_SCR, reg.REG_SZ)
        result.needs_relogon = True
        return "화면보호기 설정(다시 로그인하면 확실히 적용)"
