# Checklist template

The Word checklist form (`form_2026.docx`) is **not included** in this repository. Without it the program still
runs and writes the HTML and CSV reports; it only skips the Word checklist (the log says so).

To produce the Word checklist, put your own form here as `templates/form_2026.docx`
(and next to the executable as `templates\form_2026.docx` after building). Type each placeholder below into the
cell where its value should appear, in one go, without changing formatting inside it (Word splits text into runs).
The program checks at start-up that all placeholders are present.

| Placeholder | Value |
|---|---|
| `{{SYS_NAME}}`, `{{PURPOSE}}`, `{{ASSET_NO}}`, `{{MAC}}` | inspection info |
| `{{TYPE_NEW}}`, `{{TYPE_REG}}`, `{{TYPE_ADHOC}}` | ■ / □ for the inspection type (new / regular / ad hoc) |
| `{{DATE}}` | inspection date |
| `{{EXCEPTIONS}}` | items marked as exceptions, with reason and mitigation |
| `{{R_PC01}}` … `{{R_PC22}}` | result mark (〇 / △ / X) |
| `{{N_PC01}}` … `{{N_PC22}}` | note |
| `{{FOLDER}}` | storage folder name (evidence appendix) |
| `{{EB_PC00}}`, `{{EN_PC00}}` | PC-00 evidence file / note |
| `{{EB_PCxx}}`, `{{EA_PCxx}}`, `{{EN_PCxx}}` | evidence before / after / note for PC-01 … PC-22 (no PC-20) |

Total: 119 placeholders. Values are filled in Korean.
