from .base import Check, Status, run_ps


class PC07(Check):
    code, title, category, severity = "PC-07", "파일 시스템이 NTFS 포맷으로 설정", "2. 서비스 관리", "중"
    guide = "FAT32 볼륨은 데이터 백업 후 'convert X: /fs:ntfs'로 변환."

    def check(self, ctx):
        rows = run_ps(
            "$bus=@{}; Get-Partition -ErrorAction SilentlyContinue | Where-Object DriveLetter | ForEach-Object {"
            " $bus[[string]$_.DriveLetter] = [string](Get-Disk -Number $_.DiskNumber).BusType };"
            "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {"
            " [pscustomobject]@{Id=$_.DeviceID; Fs=$_.FileSystem; Bus=$bus[$_.DeviceID.Substring(0,1)]} }")
        fixed = [d for d in rows if (d.get("Bus") or "") != "USB"]
        bad = [f"{d['Id']}({d.get('Fs') or '알 수 없음'})" for d in fixed if (d.get("Fs") or "").upper() != "NTFS"]
        r = self.new(expected="모든 고정 디스크 NTFS(USB 연결 디스크 제외)",
                     current=", ".join(f"{d['Id']} {d.get('Fs')}" for d in fixed) or "고정 디스크 없음",
                     evidence=[f"{d['Id']} {d.get('Fs')} BusType={d.get('Bus')}" for d in rows])
        r.status = Status.VULN if bad else (Status.GOOD if fixed else Status.NA)
        if bad:
            r.note = "NTFS 아님: " + ", ".join(bad)
        return r
