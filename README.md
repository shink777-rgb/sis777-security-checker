# SIS777 Security Checker

A Windows 10/11 desktop tool that checks a PC against the 22 items (PC-01 to PC-22) of the Korean
*PC security guideline* (PC보안권고문), fixes the items that can be fixed safely, and produces the Korean
"Operation/Development PC security checklist" as a Word document — with screenshot evidence for every item.

It is designed to run **only from an external USB drive** and to leave **nothing on the inspected PC**:
all results, backups, logs and evidence are written to a folder on the USB.

> **Language note.** The user interface, logs and source code are in English. The check items, criteria,
> verdicts, reports (HTML/CSV), evidence text and the Word checklist stay in **Korean**, because they reproduce
> a Korean guideline and an official Korean form.

## Features

- **9-step automatic run** with a progress screen; it stops only when a decision is needed (modal pop-ups,
  the default button is always the safe choice).
- **22 checks** (registry, local security policy, services, shares, firewall, antivirus via Security Center,
  Windows build support dates per edition, …). Items that cannot be read from Windows are asked as self-check
  questions (e.g. PC-20 CMOS password).
- **Auto-fix** for 12 items, after a confirmation list. Every change is journaled first and can be reverted with
  **[Restore]**. Items managed by Group Policy or a security product, and items marked as exceptions, are never changed.
- **Evidence screenshots** — for each item the commands behind the verdict run in a console window that is captured
  (PNG + TXT), before and after auto-fix. PC-00 captures *Settings > System > About*.
- **Word checklist** filled with the results, plus an evidence appendix — the form itself is not included,
  see [templates/README.md](templates/README.md); **HTML** and **CSV** reports; **SQLite** history per PC.
- **Run-from-USB only** (bus type must be USB; network, optical, subst and virtual drives are refused),
  optional **registered-USB** restriction, and a **launch password**.
- Standard library only at run time (tkinter, ctypes, winreg, sqlite3, zipfile); Windows PowerShell 5.1 for queries.

## Items

| Code | Item (short English name) | Auto-fix |
|---|---|:-:|
| PC-01 | Password maximum age (90 days) | ✓ |
| PC-02 | Password policy (complexity, minimum length) | ✓ |
| PC-03 | No automatic logon in the Recovery Console | ✓ |
| PC-04 | Remove shared folders | ✓ (default shares) |
| PC-05 | Remove unnecessary services | ✓ |
| PC-06 | No unauthorized commercial messengers | |
| PC-07 | NTFS file system | |
| PC-08 | No multi-boot into other OSes | |
| PC-09 | Delete temporary internet files when the browser closes | ✓ |
| PC-10 | Regular security patches | |
| PC-11 | Supported Windows build | |
| PC-12 | No Windows auto-logon | ✓ |
| PC-13 | Antivirus installed and up to date | |
| PC-14 | Antivirus real-time protection | |
| PC-15 | Windows firewall on | ✓ |
| PC-16 | Screen saver timeout and password | ✓ |
| PC-17 | AutoRun/AutoPlay disabled for removable media | ✓ |
| PC-18 | Remote Assistance disabled | ✓ |
| PC-19 | SafeUSB (media control) installed | |
| PC-20 | Boot (CMOS) password, 9+ characters — self-check | |
| PC-21 | Monthly self-inspection | |
| PC-22 | Remove Xbox Game Bar | ✓ (irreversible) |

Thresholds and lists (password length, patch age, antivirus signature age, services, messengers, Windows support
dates, …) live in [`config/criteria.json`](config/criteria.json) and can be changed without touching the code.

## Requirements

- Windows 10 or 11 (Home, Pro, Enterprise, Education, Enterprise LTSC). Server editions are refused.
- Administrator rights (the executable requests elevation).
- To build: Python 3.11+ and PyInstaller (`pip install pyinstaller`).

## Build

```bat
build.bat
```

The script runs the unit tests, builds a one-folder executable with PyInstaller and copies `config/` and
`templates/` next to it (add your own `templates/form_2026.docx` first if you want the Word checklist). Copy the whole `dist\SIS777\` folder to the USB drive. The build status is written to
`build_status.txt` (OK/FAIL) and the log to `build_log.txt`.

## Usage

1. Plug in the USB drive and run `SIS777.exe` from it. Approve the administrator prompt.
2. First run: set the **launch password** (8+ characters). It is asked on every launch; five wrong attempts lock it
   for 10 minutes. Change it with **[Change password]**.
3. Press **[Start]**. Enter the system name (required — it becomes the storage folder name), purpose, asset number,
   MAC address and inspection type, answer the self-check questions, review the auto-fix list, and wait for the reports.

### Data on the USB

```
E:\
├─ SIS777\                  program folder (SIS777.exe, _internal\, config\, templates\, usb_whitelist.json)
└─ <system name>\           one folder per inspected PC
    ├─ data\     history.db, pcinfo.json (system name, MAC list, exceptions)
    ├─ reports\  점검결과_<date>.html / .csv, 보안점검표_<date>.docx (only with a template)
    ├─ evidence\ PC-00_시스템정보_<time>_1.png/.txt, <code>_조치전_<time>.png/.txt, <code>_조치후_<time>.png/.txt
    ├─ backup\   <time>\journal.json (+ .reg exports for reference)
    ├─ logs\     실행로그_<time>.log
    └─ tmp\      temporary files, emptied after each run
```

The same PC is recognised by its MAC addresses (stored in `pcinfo.json`), not by the folder name.

## Security

The program runs elevated, while the USB it runs from can be written by other software on the inspected PC.
Read [SECURITY.md](SECURITY.md) before using it — in particular, **protect the USB with a BitLocker To Go password**
and remove it as soon as an inspection is finished.

## Tests

```
python -m unittest discover -s tests -v
```

Most tests run on any OS (verdict logic, storage, journal validation, Word checklist, a simulated 9-step run).
Two tests run only on Windows (PowerShell syntax check of all evidence scripts, BitLocker status query).

## Status

- Verdict logic, reports and the pipeline are covered by unit tests; the evidence capture and PC-00 screenshot were
  verified on a Windows 11 PC.
- A full inspection-and-auto-fix test on real PCs / VMs of every supported edition has **not** been done yet.
  Try it on a test machine first.
- The Windows support table (`os_support` in `criteria.json`) was checked against Microsoft lifecycle information on
  2026-11-18 and must be reviewed regularly.

## Disclaimer

This tool changes Windows security settings. Use it at your own risk, test it first, and keep the backups it creates.
It is a personal project and is not an official tool of any organization.

## License

[MIT](LICENSE)
