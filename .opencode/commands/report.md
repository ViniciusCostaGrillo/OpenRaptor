---
description: Gerar relatórios de Bug Bounty (HackerOne/Bugcrowd) e Pentest (Markdown + HTML)
agent: build
---

# /report — Gerador de Relatórios Bug Bounty & Pentest

Confirme com o usuário o diretório de saída (`--out <out-dir>`), o alvo (`--target`) e a plataforma (`generic`, `hackerone`, `bugcrowd`).

Execute após aprovação:
```bash
python3 raptor.py report --out <out-dir> --target <alvo> --platform <generic|hackerone|bugcrowd>
```

Os arquivos gerados em `<out-dir>` são:
- `bounty-report.md` (pronto para submissão)
- `pentest-report.md` (executivo + técnico)
- `pentest-report.html` (visualização formatada)
