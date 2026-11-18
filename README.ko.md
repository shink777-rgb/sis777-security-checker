# SIS777 보안점검프로그램 (한국어 안내)

PC보안권고문 22개 항목(PC-01~PC-22)을 점검하고, 자동 설정이 가능한 취약 항목을 권고 기준에 맞게 설정하며,
「운영·개발PC 보안점검표」를 Word로 만들어 주는 Windows 10/11 프로그램입니다. 영문 설명은 [README.md](README.md)를 보세요.

- 프로그램 화면·로그·소스는 영문, 점검 항목·판정·보고서·증빙·점검표는 한국어입니다.
- USB 외장 드라이브에서만 실행되며, 모든 결과는 USB의 `<시스템명>` 폴더에 저장됩니다(PC에는 저장하지 않음).
- 실행할 때마다 실행 암호를 입력합니다(처음 실행 때 설정, 5번 틀리면 10분 잠김).
- USB 자체에 BitLocker To Go 암호를 거는 것을 권장합니다. 자세한 내용은 [SECURITY.md](SECURITY.md)를 보세요.

빌드: `build.bat` 실행 → `dist\SIS777\` 폴더를 USB에 복사.
테스트: `python -m unittest discover -s tests -v`
라이선스: [MIT](LICENSE)

※ 보안점검표 Word 양식(`templates/form_2026.docx`)은 이 저장소에 포함되어 있지 않습니다. 양식이 없으면 HTML·CSV 보고서만 만들고 Word 점검표는 건너뜁니다. 직접 양식을 넣는 방법은 [templates/README.md](templates/README.md)를 보세요.
