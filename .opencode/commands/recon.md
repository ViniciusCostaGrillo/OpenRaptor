---
description: Reconhecimento externo em escopo (subfinder, nmap, httpx, katana)
agent: build
---

# /recon — Reconhecimento Externo (Kali Linux)

Antes de rodar qualquer ferramenta de reconhecimento, **confirme com o usuário** o alvo, o escopo (`--scope scope.json` se aplicável) e quais ferramentas serão executadas (`subfinder`, `nmap`, `httpx`, `katana`).

Execute após aprovação explícita do operador:
```bash
libexec/raptor-run-lifecycle start recon --target "<alvo>"
python3 raptor.py recon --target <alvo> [--scope scope.json] --out "$OUTPUT_DIR" [--tool all|subfinder|nmap|httpx|katana] --approved
libexec/raptor-run-lifecycle complete "$OUTPUT_DIR"
```

Apresente os subdomínios, portas abertas, tecnologias HTTP e endpoints descobertos, filtrados pelo `Scope Guard`.
