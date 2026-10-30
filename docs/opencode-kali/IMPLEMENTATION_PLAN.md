# RAPTOR Fork Nativo OpenCode para Kali Linux — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transformar o repositório RAPTOR em um fork autônomo nativo do OpenCode (`opencode.ai`), desacoplado do Claude Code e pronto para execução em ambientes Kali Linux.

**Architecture:** A camada de interface do Claude Code é substituída por artefatos nativos do OpenCode (`AGENTS.md`, `.opencode/commands/`, `.opencode/agents/`, `opencode.json`). A pasta de skills é canônica na raiz (`skills/`), o launcher `bin/raptor` executa o `opencode` com gerenciamento de sessão e traps POSIX, o módulo `core/llm/opencode_adapter.py` fornece execução headless via `opencode run --format json`, e um instalador `setup-kali.sh` automatiza o provisionamento completo de pacotes apt, uv e scanners no Kali Linux.

**Tech Stack:** Python 3.12+, uv, Node.js 18+, OpenCode CLI (`opencode`), Bash 5, Semgrep, AFL++, Radare2/Rizin, GDB, Z3, Linux Namespaces/Landlock.

**Spec:** `docs/superpowers/specs/2026-10-29-raptor-opencode-kali-fork-design.md`

## Global Constraints

- Sistema Operacional alvo: Kali Linux / Debian-based x86_64 e arm64.
- Compatibilidade estrita com especificações do OpenCode (`AGENTS.md`, `.opencode/`, `opencode.json`).
- Nenhuma quebra no modelo de isolamento de segurança (`_RAPTOR_TRUSTED=1`, session token, `raptor-trust-check`).
- Manutenção da paridade total dos 39 comandos originais do RAPTOR.
- Execução de testes unitários existentes com `pytest`.

## Review Focus

1. **Resolução de caminhos em `skills/`**: código Python procurando `.claude/skills/` deve resolver na nova pasta `skills/` sem lançar `FileNotFoundError`.
2. **Subprocess output parsing em `opencode_adapter.py`**: se o `opencode run --format json` emitir múltiplas linhas ou blocos não-JSON de logs, o parser deve extrair os eventos válidos sem crashar.
3. **Persistência de variáveis de sessão e trust markers**: o OpenCode deve herdar `_RAPTOR_TRUSTED=1` e `RAPTOR_SESSION_TOKEN` de modo que scripts em `libexec/*` não abortem por permissão.
4. **Comandos com argumentos vazios vs argumentos complexos**: slash commands chamados sem flags (ex: `/scan` puro) devem acionar a resolução de target padrão documentada em `AGENTS.md` sem quebras de sintaxe no template `$ARGUMENTS`.
5. **Idempotência do `setup-kali.sh`**: rodar o instalador múltiplas vezes no Kali não deve corromper configs nem duplicar entradas no PATH.

---

### Task 1: Reestruturação Canônica de Skills e Submódulo Git

**Files:**
- Create: `skills/` (diretório movido de `.claude/skills/`)
- Modify: `.gitmodules`
- Modify: `core/audit/validate.py`
- Modify: `core/orchestration/agentic_passes.py`
- Modify: `packages/binary_analysis/blamed_lines.py`
- Test: `tests/test_skills_structure.py`

**Interfaces:**
- Consumes: Estrutura legada em `.claude/skills/`
- Produces: `skills/` canônica na raiz do projeto com caminhos Python atualizados.

- [ ] **Step 1: Escrever teste de verificação da estrutura de skills**

```python
# tests/test_skills_structure.py
from pathlib import Path

def test_skills_canonical_root():
    root = Path(__file__).resolve().parent.parent
    skills_dir = root / "skills"
    assert skills_dir.is_dir(), "skills/ deve existir na raiz"
    assert (skills_dir / "exploitability-validation").is_dir()
    assert (skills_dir / "SecOpsAgentKit").exists()
```

- [ ] **Step 2: Executar teste e verificar que falha**

Run: `pytest tests/test_skills_structure.py -v`
Expected: FAIL com `skills/ deve existir na raiz`.

- [ ] **Step 3: Mover `.claude/skills/` para `skills/` e atualizar referências em Python e Git**

1. Mover diretório `.claude/skills` para `skills` na raiz do projeto.
2. Atualizar `.gitmodules` substituindo `.claude/skills/SecOpsAgentKit` por `skills/SecOpsAgentKit`.
3. Atualizar referências de caminho em `core/audit/validate.py`, `core/orchestration/agentic_passes.py` e `packages/binary_analysis/blamed_lines.py` para apontar para `skills/`.

- [ ] **Step 4: Executar testes de validação de skills**

Run: `pytest tests/test_skills_structure.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skills .gitmodules core/ packages/ tests/test_skills_structure.py
git commit -m "refactor: relocate skills to canonical root directory and update references"
```

---

### Task 2: Instruções do Agente (`AGENTS.md`) e Configuração do OpenCode (`opencode.json`)

**Files:**
- Create: `AGENTS.md`
- Create: `opencode.json`
- Test: `tests/test_opencode_config.py`

**Interfaces:**
- Consumes: Regras de `CLAUDE.md` adaptadas para o OpenCode.
- Produces: `AGENTS.md` para instruções de sessão e `opencode.json` para permissões e env.

- [ ] **Step 1: Escrever teste para validar AGENTS.md e opencode.json**

```python
# tests/test_opencode_config.py
import json
from pathlib import Path

def test_opencode_json_validity():
    root = Path(__file__).resolve().parent.parent
    config_file = root / "opencode.json"
    assert config_file.is_file(), "opencode.json deve existir"
    with open(config_file, encoding="utf-8") as f:
        data = json.load(f)
    assert data.get("permission", {}).get("bash") == "allow"
    assert data.get("env", {}).get("_RAPTOR_TRUSTED") == "1"

def test_agents_md_rules():
    root = Path(__file__).resolve().parent.parent
    agents_file = root / "AGENTS.md"
    assert agents_file.is_file(), "AGENTS.md deve existir"
    content = agents_file.read_text(encoding="utf-8")
    assert "SESSION START" in content
    assert "EXECUTION RULES" in content
    assert "SLASH-COMMAND DISPATCH" in content
```

- [ ] **Step 2: Executar teste e verificar que falha**

Run: `pytest tests/test_opencode_config.py -v`
Expected: FAIL com arquivos inexistentes.

- [ ] **Step 3: Criar `opencode.json` e `AGENTS.md`**

1. Criar `opencode.json` definindo auto-aprovação para ferramentas (`bash`, `read`, `write`, `edit`, `glob`, `grep`) e declarando `_RAPTOR_TRUSTED: "1"`.
2. Criar `AGENTS.md` migrando o conteúdo de `CLAUDE.md`, adaptando as referências ao Claude Code para OpenCode e instruindo o agente sobre banner de início de sessão, target resolution e execução estrita de `libexec/*`.

- [ ] **Step 4: Executar testes de validação**

Run: `pytest tests/test_opencode_config.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add AGENTS.md opencode.json tests/test_opencode_config.py
git commit -m "feat: add AGENTS.md and opencode.json configuration"
```

---

### Task 3: Migração Completa de Slash Commands para `.opencode/commands/`

**Files:**
- Create: `.opencode/commands/*.md` (39 comandos)
- Test: `tests/test_opencode_commands.py`

**Interfaces:**
- Consumes: `.claude/commands/*.md` (39 comandos legados)
- Produces: `.opencode/commands/*.md` compatíveis com o formato OpenCode.

- [ ] **Step 1: Escrever teste de integridade para todos os 39 comandos**

```python
# tests/test_opencode_commands.py
from pathlib import Path

EXPECTED_COMMANDS = [
    "agentic", "analyze", "annotate", "ask", "audit", "binary", "codeql",
    "commands", "crash-analysis", "create-skill", "cve-diff", "cve-env",
    "describe", "diagram", "exploit", "frida", "fuzz", "gadget-scan",
    "ghidra", "may-ask", "openant", "oss-forensics", "patch", "project",
    "raptor", "review", "sage", "sandbox", "sca", "scan", "scorecard",
    "seatbelt", "self-test", "study", "threat-model", "tune", "understand",
    "validate", "version"
]

def test_all_commands_exist():
    root = Path(__file__).resolve().parent.parent
    cmd_dir = root / ".opencode" / "commands"
    assert cmd_dir.is_dir(), ".opencode/commands/ deve existir"
    for cmd in EXPECTED_COMMANDS:
        cmd_file = cmd_dir / f"{cmd}.md"
        assert cmd_file.is_file(), f"Comando {cmd}.md deve existir em .opencode/commands/"
        content = cmd_file.read_text(encoding="utf-8")
        assert content.startswith("---"), f"{cmd}.md deve ter frontmatter YAML"
        assert "description:" in content
```

- [ ] **Step 2: Executar teste e verificar que falha**

Run: `pytest tests/test_opencode_commands.py -v`
Expected: FAIL informando diretório ou arquivos ausentes.

- [ ] **Step 3: Gerar e converter os 39 arquivos de comandos para `.opencode/commands/`**

1. Criar `.opencode/commands/`.
2. Para cada comando em `.claude/commands/*.md`, converter para o formato OpenCode com:
   - Frontmatter YAML com `description` e `agent: build`.
   - Corpo Markdown preservando as instruções técnicas, tabelas de flags e adicionando templates de despacho executando `libexec/raptor-*` ou `python3 raptor.py *` usando `$ARGUMENTS`.
   - Garantir que `/raptor.md`, `/agentic.md`, `/scan.md`, `/fuzz.md`, etc., estejam todos presentes.

- [ ] **Step 4: Executar testes de validação dos comandos**

Run: `pytest tests/test_opencode_commands.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .opencode/commands tests/test_opencode_commands.py
git commit -m "feat: migrate all 39 slash commands to .opencode/commands"
```

---

### Task 4: Migração de Subagentes para `.opencode/agents/`

**Files:**
- Create: `.opencode/agents/*.md` (subagentes)
- Test: `tests/test_opencode_agents.py`

**Interfaces:**
- Consumes: `.claude/agents/*.md`
- Produces: `.opencode/agents/*.md` com `mode: subagent`.

- [ ] **Step 1: Escrever teste de integridade dos subagentes**

```python
# tests/test_opencode_agents.py
from pathlib import Path

def test_agents_structure():
    root = Path(__file__).resolve().parent.parent
    agents_dir = root / ".opencode" / "agents"
    assert agents_dir.is_dir(), ".opencode/agents deve existir"
    expected = [
        "exploitability-validator-agent.md",
        "offsec-specialist.md",
        "audit-reviewer.md",
        "crash-analysis-agent.md"
    ]
    for agent in expected:
        agent_file = agents_dir / agent
        assert agent_file.is_file(), f"{agent} deve existir"
        content = agent_file.read_text(encoding="utf-8")
        assert "mode: subagent" in content
```

- [ ] **Step 2: Executar teste e verificar que falha**

Run: `pytest tests/test_opencode_agents.py -v`
Expected: FAIL.

- [ ] **Step 3: Converter e salvar os subagentes em `.opencode/agents/`**

1. Criar `.opencode/agents/`.
2. Copiar e converter cada agente de `.claude/agents/`, adaptando o frontmatter YAML para `mode: subagent` e mantendo os prompts e metodologias (como os MUST-GATEs do exploitability validator).

- [ ] **Step 4: Executar testes de validação dos agentes**

Run: `pytest tests/test_opencode_agents.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .opencode/agents tests/test_opencode_agents.py
git commit -m "feat: migrate specialized subagents to .opencode/agents"
```

---

### Task 5: Implementação do Adapter Subprocesso `OpenCodeProvider`

**Files:**
- Create: `core/llm/opencode_adapter.py`
- Modify: `core/llm/providers.py`
- Test: `core/llm/tests/test_opencode_adapter.py`

**Interfaces:**
- Consumes: CLI `opencode run --format json`
- Produces: `OpenCodeProvider` implementando a interface `LLMProvider` em `core/llm/providers.py`.

- [ ] **Step 1: Escrever teste unitário para `opencode_adapter.py`**

```python
# core/llm/tests/test_opencode_adapter.py
from unittest.mock import patch, MagicMock
from core.llm.opencode_adapter import parse_opencode_json_stream, run_opencode_turn

def test_parse_opencode_json_stream():
    sample_stream = (
        '{"type":"step_start"}\n'
        '{"type":"text","content":"Vulnerabilidade detectada: SQL Injection"}\n'
        '{"type":"step_finish"}\n'
    )
    result = parse_opencode_json_stream(sample_stream)
    assert "SQL Injection" in result

@patch("subprocess.Popen")
def test_run_opencode_turn(mock_popen):
    mock_proc = MagicMock()
    mock_proc.communicate.return_value = (
        '{"type":"text","content":"Resposta segura"}'.encode("utf-8"),
        b""
    )
    mock_proc.returncode = 0
    mock_popen.return_value = mock_proc
    output = run_opencode_turn("Analise o código", model="mock-model")
    assert "Resposta segura" in output
```

- [ ] **Step 2: Executar teste e verificar que falha**

Run: `pytest core/llm/tests/test_opencode_adapter.py -v`
Expected: FAIL com `ModuleNotFoundError: No module named 'core.llm.opencode_adapter'`.

- [ ] **Step 3: Implementar `core/llm/opencode_adapter.py` e plugar em `core/llm/providers.py`**

1. Criar `core/llm/opencode_adapter.py` com:
   - `run_opencode_turn(prompt: str, model: str | None = None, system: str | None = None) -> str`
   - `parse_opencode_json_stream(stream_output: str) -> str`
   - Tratamento de timeouts, codificação UTF-8 e redaction de credenciais sensíveis.
2. Registrar a classe `OpenCodeProvider` em `core/llm/providers.py` implementando o método de geração e estruturação de JSON.

- [ ] **Step 4: Executar testes do adapter**

Run: `pytest core/llm/tests/test_opencode_adapter.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/llm/opencode_adapter.py core/llm/providers.py core/llm/tests/test_opencode_adapter.py
git commit -m "feat: implement OpenCode headless subprocess provider and adapter"
```

---

### Task 6: Atualização do Launcher `bin/raptor` e Generalização de Trust Checks

**Files:**
- Modify: `bin/raptor`
- Modify: `libexec/raptor-cc-trust-check` -> `libexec/raptor-trust-check`
- Modify: `core/security/cc_trust.py`
- Test: `tests/test_launcher_trust.py`

**Interfaces:**
- Consumes: `opencode` CLI e variáveis de sessão RAPTOR
- Produces: Launcher atualizado invocando `opencode` com traps de saída POSIX e auditoria de repositórios alvos.

- [ ] **Step 1: Escrever teste de integridade do launcher e trust checker**

```python
# tests/test_launcher_trust.py
from pathlib import Path

def test_launcher_invokes_opencode():
    root = Path(__file__).resolve().parent.parent
    launcher = root / "bin" / "raptor"
    content = launcher.read_text(encoding="utf-8")
    assert "opencode" in content, "bin/raptor deve invocar o binário opencode"
    assert "trap" in content, "bin/raptor deve ter trap de saída para lifecycle hook"
```

- [ ] **Step 2: Executar teste e verificar que falha**

Run: `pytest tests/test_launcher_trust.py -v`
Expected: FAIL.

- [ ] **Step 3: Atualizar `bin/raptor` e trust checks**

1. Modificar `bin/raptor`:
   - Configurar trap Bash: `trap '"$RAPTOR_DIR/libexec/raptor-lifecycle-hook" session-end' EXIT INT TERM`.
   - Executar `"$RAPTOR_DIR/libexec/raptor-session-init"`.
   - Substituir a invocação final `exec claude ...` por `exec opencode "$@"`.
2. Generalizar `libexec/raptor-cc-trust-check` e `core/security/cc_trust.py` para inspecionar arquivos maliciosos de configuração tanto de `.opencode/` quanto `.claude/` no repositório inspecionado.

- [ ] **Step 4: Executar testes de validação**

Run: `pytest tests/test_launcher_trust.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/raptor libexec/ core/security/ tests/test_launcher_trust.py
git commit -m "feat: update bin/raptor to launch opencode and generalize target trust checks"
```

---

### Task 7: Script Automatizado de Provisionamento para Kali Linux (`setup-kali.sh`)

**Files:**
- Create: `setup-kali.sh`
- Test: `tests/test_kali_setup_script.py`

**Interfaces:**
- Consumes: Sistema operacional Kali Linux / Debian
- Produces: Script bash idempotente que prepara todo o ambiente.

- [ ] **Step 1: Escrever teste de validação estática do script `setup-kali.sh`**

```python
# tests/test_kali_setup_script.py
from pathlib import Path

def test_setup_kali_script_syntax():
    root = Path(__file__).resolve().parent.parent
    script = root / "setup-kali.sh"
    assert script.is_file(), "setup-kali.sh deve existir"
    content = script.read_text(encoding="utf-8")
    assert "#!/usr/bin/env bash" in content
    assert "apt-get install" in content
    assert "uv" in content
    assert "semgrep" in content
    assert "opencode" in content
```

- [ ] **Step 2: Executar teste e verificar que falha**

Run: `pytest tests/test_kali_setup_script.py -v`
Expected: FAIL com arquivo inexistente.

- [ ] **Step 3: Criar `setup-kali.sh`**

Implementar o script em bash:
- Verificação e elevação via `sudo`.
- `apt-get update && apt-get install -y python3 python3-pip python3-venv build-essential curl git jq rizin radare2 aflplusplus gdb libseccomp-dev`.
- Instalação do `uv` caso não exista: `curl -LsSf https://astral.sh/uv/install.sh | sh`.
- Sincronização do ambiente Python: `uv sync --locked`.
- Instalação do `opencode` se não presente no PATH: `curl -fsSL https://opencode.ai/install | bash`.
- Instalação de ferramentas via uv: `uv tool install semgrep`.
- Aplicação de `chmod +x` em `bin/raptor` e `libexec/*`.
- Exibição de mensagem de boas-vindas com instruções para adicionar `bin` ao `PATH`.

- [ ] **Step 4: Executar testes de validação do script**

Run: `pytest tests/test_kali_setup_script.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add setup-kali.sh tests/test_kali_setup_script.py
git commit -m "feat: add automated setup script for Kali Linux"
```

---

### Task 8: Limpeza de Artefatos Legados e Atualização da Documentação (`README.md`)

**Files:**
- Delete: `.claude/`
- Delete: `CLAUDE.md`
- Modify: `README.md`
- Test: `tests/test_clean_state.py`

**Interfaces:**
- Consumes: Repositório com novos artefatos OpenCode
- Produces: Repositório 100% limpo, sem resíduos legados do Claude Code e com documentação atualizada para Kali Linux e OpenCode.

- [ ] **Step 1: Escrever teste para garantir ausência de resíduos legados**

```python
# tests/test_clean_state.py
from pathlib import Path

def test_no_legacy_claude_artifacts():
    root = Path(__file__).resolve().parent.parent
    assert not (root / ".claude").exists(), ".claude/ deve ser completamente removido"
    assert not (root / "CLAUDE.md").exists(), "CLAUDE.md deve ser substituído por AGENTS.md"
```

- [ ] **Step 2: Executar teste e verificar que falha**

Run: `pytest tests/test_clean_state.py -v`
Expected: FAIL informando que `.claude` e `CLAUDE.md` ainda existem.

- [ ] **Step 3: Remover `.claude/` e `CLAUDE.md` e atualizar `README.md`**

1. Remover `.claude/` e `CLAUDE.md`.
2. Atualizar `README.md` ajustando o banner, pré-requisitos (OpenCode, Kali Linux, uv, Semgrep), instruções de instalação com `./setup-kali.sh` e exemplos de comandos do OpenCode.

- [ ] **Step 4: Executar suite de testes completa**

Run: `pytest tests/ -v`
Expected: PASS em todos os testes.

- [ ] **Step 5: Commit**

```bash
git rm -r .claude CLAUDE.md
git add README.md tests/test_clean_state.py
git commit -m "chore: remove legacy claude code artifacts and update documentation for OpenCode and Kali"
```
