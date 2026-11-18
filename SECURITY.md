# Security notes

SIS777 runs with administrator rights on the PC being inspected, but its program files, settings and backup
records live on a USB drive. The design choices and the remaining risks are listed here.

## Threat model

| Risk | Mitigation |
|---|---|
| **Lost or borrowed USB** — anyone could open and change the program, `criteria.json`, backups or results. | Protect the USB with a **BitLocker To Go password**. At step 1 the program checks the BitLocker state of the USB and shows a recommendation if it is not protected. |
| **Tampering while the USB is unlocked** — other programs on the inspected PC (including malware) can write to the USB. A modified program would run elevated next time, possibly on another PC. | Remove the USB as soon as the inspection is finished. The executable cannot verify itself (its DLLs load first). For stronger protection use a hardware-encrypted USB with a read-only mode. |
| **Swapping a script file between write and execution** | No script files are written. PowerShell scripts are passed with `-EncodedCommand`; the evidence-window script is passed through a process-private environment variable. |
| **PowerShell injection through names** (installed program names, service names, …) | `ps_quote()` doubles `'` and the typographic quotes `‘ ’ ‚ ‛` that PowerShell also treats as quotes, and strips NUL; search patterns are regex-escaped (`ps_regex()`). Service names are validated before use. |
| **Tampered restore journal** (`journal.json`) | Restore only touches an allow-list: the registry paths/value names this program changes, value types REG_SZ/EXPAND_SZ/DWORD with range checks, `.scr` files for the screen saver, 8 security-policy keys with integer values, the 3 firewall profiles, and validated service/account names. Anything else is skipped and reported. |
| **Executable search order** — bare names like `net` would run a same-named file from the program folder first. | Console tools are run from System32 by full path; the Windows directory comes from `GetSystemWindowsDirectoryW`, not from `%SystemRoot%`. |
| **secedit `.inf` swapped while being applied** | Random file name, content compared right before and right after `secedit /configure`; values limited to allowed keys and integers. |
| **CSV formula injection** | Values starting with `= + - @` (or tab/CR) are prefixed with `'`. |

## Passwords and the registered-USB list

- The launch password (also used for **[Register USB]**) is stored as PBKDF2-SHA256 (200,000 iterations, random salt)
  in `usb_whitelist.json`, compared in constant time; five failures lock it for ten minutes.
- Registered USB serials are stored only as HMAC values. The HMAC key is built into the program and is public in this
  repository, so the registered-USB list and the launch password are **usage-policy aids, not security boundaries**:
  anyone who can write to the program folder can delete `usb_whitelist.json` and start over.
  They become meaningful only together with a BitLocker-protected USB.

## Privacy

- No network code: the program never sends data anywhere.
- The auto-logon password (`DefaultPassword`) is never read, shown, logged or backed up — only its presence is reported.
- Results contain the computer name, user name, IP and MAC addresses, device and product IDs. Treat the USB and the
  reports as confidential.

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security → Advisories) instead of a public issue.
