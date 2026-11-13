---
description: Análise de APK Android (Manifest, endpoints, segredos) + handoff de libs .so para Ghidra/REA
agent: build
---

# /mobile — Análise de APK & Ponte Ghidra/REA

Antes de executar, **confirme com o usuário** o caminho do arquivo `.apk`.

Execute após aprovação explícita do operador:
```bash
libexec/raptor-run-lifecycle start mobile --target "<caminho.apk>"
python3 raptor.py mobile --apk <caminho.apk> --out "$OUTPUT_DIR"
libexec/raptor-run-lifecycle complete "$OUTPUT_DIR"
```

Após a extração:
- Apresente flags inseguras do `AndroidManifest.xml`, componentes exportados sem permissão, endpoints e segredos encontrados.
- Se houver bibliotecas nativas (`ghidra_targets` em `.so`), pergunte ao usuário se deseja analisá-las agora via **REA MCP** (preferencial quando disponível) ou via `python3 raptor.py ghidra import <lib.so>`.
