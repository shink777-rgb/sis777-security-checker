@echo off
chcp 65001 > nul
REM ============================================================
REM  SIS777 Security Checker build (run on the development PC)
REM  Needs: Python 3.11+, PyInstaller
REM  Output: dist\SIS777\ folder -> copy the whole folder to the USB
REM  Log: build_log.txt, result: build_status.txt (OK / FAIL)
REM ============================================================
cd /d "%~dp0"
echo RUNNING> build_status.txt
echo Building SIS777... (log: build_log.txt)

echo [1/3] Unit tests> build_log.txt
python -m unittest discover -s tests >> build_log.txt 2>&1
if errorlevel 1 (
  echo [STOP] unit tests failed>> build_log.txt
  echo FAIL> build_status.txt
  exit /b 1
)

REM One-folder build (--onedir): a one-file build unpacks into %%TEMP%% on the PC, which we avoid
echo [2/3] PyInstaller>> build_log.txt
python -m PyInstaller --noconfirm --clean --onedir --windowed --uac-admin --name SIS777 main.py >> build_log.txt 2>&1
if errorlevel 1 (
  echo [STOP] PyInstaller failed>> build_log.txt
  echo FAIL> build_status.txt
  exit /b 1
)

REM Criteria and template sit next to the executable (criteria.json is updated at run time, e.g. SafeUSB names)
echo [3/3] Copy config and template>> build_log.txt
xcopy /e /i /y config dist\SIS777\config >> build_log.txt
xcopy /e /i /y templates dist\SIS777\templates >> build_log.txt
copy /y README.md dist\SIS777\ >> build_log.txt
copy /y LICENSE dist\SIS777\ >> build_log.txt

echo Done: dist\SIS777\SIS777.exe>> build_log.txt
echo OK> build_status.txt
echo Done: copy the dist\SIS777\ folder to the external USB drive.
timeout /t 5 > nul
