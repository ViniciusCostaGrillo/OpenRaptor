# Design Document: RAPTOR Fork Nativo OpenCode para Kali Linux

- **Data:** 2026-10-29
- **Status:** Aprovado para Planejamento
- **Alvo:** Kali Linux & OpenCode (`opencode.ai`)

---

## 1. Contexto e Motivação

O **RAPTOR** (Recursive Autonomous Penetration Testing and Observation Robot) é um framework avançado de segurança ofensiva e defensiva que combina scanners estáticos (Semgrep, CodeQL), fuzzing binário (AFL++), análise reversa (Ghidra, Radare2/Rizin), verificação SMT e orquestração de LLMs para validar falhas, gerar exploits PoC e criar patches.

Originalmente, o RAPTOR foi fortemente acoplado ao ecossistema do **Claude Code** (`claude` CLI, subscrição Anthropic, `.claude/`, `CLAUDE.md`, `cc_adapter.py`). O objetivo deste fork é:
1. **Desvincular o RAPTOR do Claude Code**, tornando-o 100% nativo do **OpenCode** (`opencode.ai`), um agente de código open-source com suporte a múltiplos modelos (Anthropic, OpenAI, Gemini, Ollama/vLLM local).
2. **Otimizar para Kali Linux**, permitindo que pesquisadores de segurança e pentesters executem a suíte completa no sistema operacional padrão da área com dependências empacotadas de forma simples.

---

## 2. Objetivos, Não-Objetivos e Anti-Objetivos

### Objetivos
- **Migração Completa para OpenCode:**
  - Substituir `CLAUDE.md` por `AGENTS.md` (formato padrão do OpenCode para regras de sessão e instruções de execução).
  - Migrar todos os 39 slash commands de `.claude/commands/` para `.opencode/commands/` usando o formato Markdown nativo com frontmatter YAML e interpolação de `$ARGUMENTS`.
  - Migrar todos os subagentes de `.claude/agents/` para `.opencode/agents/` com `mode: subagent` e restrições de ferramentas apropriadas.
  - Relocar `.claude/skills/` para a raiz `skills/` com symlink para `.opencode/skills/`, atualizando submódulos git (`SecOpsAgentKit`) e caminhos em `core/`.
  - Criar `opencode.json` com pré-aprovação de permissões para os scripts de `libexec/*` e comandos `python3 raptor.py *`.
  - Adaptar o launcher `bin/raptor` para gerenciar as sessões, tokens e delegar a execução diretamente ao comando `opencode`.
  - Criar o adapter `opencode_adapter.py` e a classe `OpenCodeProvider` em `core/llm/providers.py` para chamadas headless via subprocesso (`opencode run --format json`).
  - Implementar plugin de cobertura `.opencode/plugins/coverage.ts` para registrar arquivos lidos durante a auditoria.
- **Suporte de Primeira Classe ao Kali Linux:**
  - Criar um script unificado de instalação e verificação `setup-kali.sh` que instala pacotes essenciais via `apt`, instala `uv`, compõe o ambiente virtual, instala o `opencode` e o `semgrep`.
  - Garantir compatibilidade total com o modelo de sandbox Linux do RAPTOR (Landlock, seccomp, namespaces) no kernel do Kali.
- **Eliminação de Dívida Técnica:**
  - Remover referências mortas e o diretório `.claude/`.

### Não-Objetivos
- **Reescrever os motores analíticos centrais:** Os scripts Python (`raptor.py`, `raptor_agentic.py`, `raptor_fuzzing.py`, `raptor_codeql.py`), os módulos em `core/` e os shims em `libexec/` realizam as análises e continuarão sendo utilizados pelo agente orquestrador.
- **Alterar o fluxo metodológico das fases de exploração:** O pipeline em estágios (0, A-F, 1) continua idêntico.

### Anti-Objetivos
- **Reduzir o rigor de segurança:** O isolamento e os trust markers (`_RAPTOR_TRUSTED`, tokens de sessão em `~/.local/share/raptor/sessions.d/`) devem ser mantidos sem atalhos inseguros. Vistoria de configurações maliciosas em repositórios alvos continua ativa (`raptor-trust-check`).
- **Acoplar a ferramenta a um único provedor de LLM:** O OpenCode suporta mais de 75 provedores; o fork deve permitir modelos locais ou em nuvem conforme configurado pelo usuário.

---

## 3. Restrições e Premissas

- **Sistema Operacional:** Kali Linux (Debian-based), arquitetura x86_64 / arm64.
- **Runtime:** Python 3.12+, Node.js 18+ (para o runtime do OpenCode), Bash 5+.
- **Ferramentas de Análise:** Semgrep, AFL++, Radare2/Rizin, GDB, CodeQL (opcional).

---

## 4. Abordagens Consideradas

### Abordagem 1: Fork Nativo OpenCode (Escolhida)
- Substituição direta de todos os artefatos do Claude Code por artefatos do OpenCode.
- **Trade-off:** Não mantém compatibilidade reversa com o Claude Code proprietário, mas produz um repositório limpo, focado, sem duplicação de configurações ou confusão operacional.

### Abordagem 2: Dual-Driver Híbrido (Descartada)
- Manutenção simultânea de `.claude/` e `.opencode/`, com seleção por flag no launcher.
- **Trade-off:** Custo de sincronização contínuo entre dois formatos de comandos, agentes e permissões; desnecessário para o propósito de criar um fork focado.

---

## 5. Especificação Técnica da Arquitetura

### 5.1 Instruções do Agente (`AGENTS.md`)
Criar o arquivo `AGENTS.md` na raiz do repositório:
- **Início da Sessão:** Imprimir banner do RAPTOR verbatim na primeira mensagem; exibir comandos rápidos (`/agentic`, `/scan`, `/fuzz`, `/web`).
- **Regras de Execução:** Execução literal de comandos sem adicionar pipes (`| grep`, etc.) ou wrappers desnecessários, garantindo preservação do sentinel `OUTPUT_DIR=<path>`.
- **Despacho de Comandos:** Mapeamento das slash commands para a chamada correspondente em `libexec/raptor-*` ou `python3 raptor.py`.
- **Governança de Sessão e Diretório Alvo:** Resolução do projeto ativo e target padrão (`core.run.output.resolve_default_target`).
- **Ciclo de Vida do Run:** Uso de `libexec/raptor-run-lifecycle` (`start`, `complete`, `fail`).

### 5.2 Configuração do OpenCode (`opencode.json`)
Localizado na raiz ou em `.opencode/opencode.json`:
```json
{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "bash": "allow",
    "read": "allow",
    "write": "allow",
    "edit": "allow",
    "glob": "allow",
    "grep": "allow"
  },
  "env": {
    "_RAPTOR_TRUSTED": "1"
  }
}
```

### 5.3 Migração de Comandos (`.opencode/commands/*.md`)
Todos os 39 comandos de `.claude/commands/*.md` serão portados:
- Frontmatter YAML com `description` e `agent: build`.
- Corpo contendo instruções operacionais e templates `$ARGUMENTS`.
- Comandos centrais: `/raptor`, `/agentic`, `/scan`, `/fuzz`, `/web`, `/codeql`, `/analyze`, `/audit`, `/understand`, `/validate`, `/exploit`, `/patch`, `/binary`, `/ghidra`, `/sca`, `/cve-diff`, `/cve-env`, `/describe`, `/threat-model`, `/diagram`, `/project`, `/review`, `/annotate`, `/sage`, `/ask`, `/openant`, `/crash-analysis`, `/scorecard`, `/oss-forensics`, `/tune`, etc.

### 5.4 Migração de Subagentes (`.opencode/agents/*.md`)
Os subagentes existentes em `.claude/agents/*.md` são transferidos para `.opencode/agents/` com a formatação:
```markdown
---
description: [Descrição da especialidade]
mode: subagent
---
[System Prompt do Especialista]
```
Especialistas incluídos:
- `exploitability-validator-agent`
- `offsec-specialist`
- `audit-reviewer`
- `crash-analysis-agent`
- `oss-forensics` agentes especialistas

### 5.5 Gestão de Skills e Submódulos (`skills/`)
- Mover `.claude/skills/` para `skills/` na raiz.
- Criar symlink `.opencode/skills -> ../../skills`.
- Atualizar `.gitmodules` para `path = skills/SecOpsAgentKit`.
- Ajustar os imports/paths em Python (`core/audit/validate.py`, `core/orchestration/agentic_passes.py`, `packages/binary_analysis/blamed_lines.py`).

### 5.6 Launcher (`bin/raptor`) e Ciclo de Vida
- Mantém isolamento inicial e sanitização de ambiente.
- Registra sessão em `~/.local/share/raptor/sessions.d/$$`.
- Executa `libexec/raptor-session-init` antes de subir o agente.
- Instala traps Bash (`trap '... raptor-lifecycle-hook session-end' EXIT INT TERM`) para evitar runs órfãos caso o processo seja interrompido.
- Executa `exec opencode "$@"`.

### 5.7 Driver Subprocesso (`core/llm/opencode_adapter.py`)
- Implementa `OpenCodeProvider` em `core/llm/providers.py` chamando `opencode run --format json`.
- Fornece suporte headless sem depender do binário proprietário `claude`.

### 5.8 Plugin de Cobertura (`.opencode/plugins/coverage.ts`)
- Plugin leve TypeScript para OpenCode que intercepta leitura de arquivos (`read`) e alimenta a telemetria de cobertura em `.raptor-coverage.json`.

### 5.9 Script de Instalação Kali Linux (`setup-kali.sh`)
Script idempotente em bash com verificação de privilégios (`sudo` onde necessário):
1. **Pacotes do Sistema (Apt):**
   ```bash
   apt-get update && apt-get install -y \
     python3 python3-pip python3-venv build-essential \
     curl git jq rizin radare2 aflplusplus gdb libseccomp-dev
   ```
2. **Ambiente Python e uv:**
   - Instalação do `uv` caso não exista.
   - Execução de `uv sync --locked` criando o `.venv`.
3. **Instalação do OpenCode:**
   - Detecção ou instalação do `opencode` (via `curl -fsSL https://opencode.ai/install | bash`).
4. **Instalação de Scanners:**
   - Instalação do `semgrep` via `uv tool install semgrep`.
5. **Permissões e PATH:**
   - Aplicação de `chmod +x` em `bin/raptor` e `libexec/*`.
   - Verificação de sanidade das ferramentas.

---

## 6. Decisões do Builder (Architectural Calls Feitas)

1. **Skills Canônicas na Raiz (`skills/`):** Os skills contêm o motor de validação (estágios 0-F) e o submódulo `SecOpsAgentKit`. Serão movidos para a raiz `skills/` e espelhados em `.opencode/skills/`, preservando a lógica dos módulos Python.
2. **Escopo dos Comandos (Total de 39):** Todos os 39 comandos existentes serão migrados para manter 100% de paridade funcional.
3. **Lifecycle via Traps no `bin/raptor`:** Para garantir que hooks de encerramento rodem mesmo sem suporte a eventos complexos no `opencode.json`, `bin/raptor` gerencia traps de saída do sistema operacional.
4. **Trust Checker de Repositórios (`raptor-trust-check`):** O script `raptor-cc-trust-check` foi generalizado para auditar arquivos `.opencode/` e `.claude/` em repositórios alvos para evitar execução de payloads arbitrários durante scans.
