# Arquitetura e Stack Tecnológica — RAPTOR Fork OpenCode / Kali Linux

## 1. Visão Arquitetural

O fork mantém o poderoso motor analítico de segurança do RAPTOR em Python e substitui a interface de interação pelo OpenCode.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      CAMADA 1: ORQUESTRADOR OPENCODE                   │
│  • CLI Interativo e Headless: `opencode` / `opencode run`              │
│  • Regras de Sessão: `AGENTS.md` (no root do repositório)              │
│  • Configurações & Permissões: `opencode.json` (auto-aprovação)        │
│  • Slash Commands: `.opencode/commands/*.md` (39 comandos)             │
│  • Subagentes Especialistas: `.opencode/agents/*.md`                   │
│  • Telemetria de Cobertura: `.opencode/plugins/coverage.ts`            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Executa shims e chamadas de subprocesso
┌───────────────────────────────────▼────────────────────────────────────┐
│                  CAMADA 2: DISPATCH & PROVEDORES LLM                   │
│  • Subprocess Adapter: `core/llm/opencode_adapter.py`                  │
│  • Provider Integrado: `OpenCodeProvider` em `core/llm/providers.py`   │
│  • Provedores Nativos Multi-Model: Claude, GPT, Gemini, Ollama, vLLM   │
│  • Consensus / Judge / Aggregator para validação de hipóteses          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Orquestra ferramentas analíticas
┌───────────────────────────────────▼────────────────────────────────────┐
│              CAMADA 3: MOTORES DE SEGURANÇA & TESTES (KALI)            │
│  • SAST: Semgrep, GitHub CodeQL, Coccinelle (`spatch`)                 │
│  • DAST & Fuzzing: AFL++ nativo, ASAN, GDB, Crash Analysis             │
│  • RE & Binários: Radare2 / Rizin, Ghidra headless                     │
│  • Verificação Formal: SMT Solver Z3 (provas matemáticas de bugs)      │
│  • SCA & CVEs: OSV, NVD, CISA KEV, EPSS via `raptor.py sca`            │
│  • Dinâmica: Frida, Web Testing (ffuf, nuclei)                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Opera sob restrições do SO
┌───────────────────────────────────▼────────────────────────────────────┐
│                 CAMADA 4: RUNTIME, SISTEMA BASE & SANDBOX              │
│  • Sistema Operacional: Kali Linux (Kernel 6.x+, Debian Rolling)       │
│  • Sandbox & Isolamento: Linux Namespaces, Seccomp BPF, Landlock       │
│  • Gerenciador de Pacotes Python: `uv` (Astral) com Python 3.12+       │
│  • Runtime JavaScript: Node.js 18+ / npm para o CLI do OpenCode        │
│  • Launcher de Sistema: `bin/raptor` (Bash 5 com Session Tokens)       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Comparativo: Claude Code vs. OpenCode no RAPTOR

| Componente | Implementação Claude Code (Original) | Implementação OpenCode (Novo Fork) |
| :--- | :--- | :--- |
| **Instruções Principais** | `CLAUDE.md` | `AGENTS.md` (padrão OpenCode lido no root) |
| **Configuração & Permissões** | `.claude/settings.json` | `opencode.json` com `permission: { bash: "allow", ... }` |
| **Slash Commands** | `.claude/commands/*.md` (formato legado) | `.opencode/commands/*.md` com YAML frontmatter e `$ARGUMENTS` |
| **Subagentes Especialistas** | `.claude/agents/*.md` | `.opencode/agents/*.md` com `mode: subagent` |
| **Skills & Validação** | `.claude/skills/` (acoplado) | `skills/` canônica na raiz + link `.opencode/skills` |
| **Subprocess LLM Driver** | `cc_adapter.py` (`claude -p`) | `opencode_adapter.py` (`opencode run --format json`) |
| **Launcher** | `bin/raptor` invocando `claude` | `bin/raptor` invocando `opencode` com traps de saída POSIX |
| **Instalação no Kali Linux** | Manual com múltiplas etapas | Automatizada via `./setup-kali.sh` |

---

## 3. Segurança e Isolamento

O RAPTOR analisa códigos não-confiáveis e executa PoCs. O modelo de isolamento no Kali Linux é mantido rigorosamente:
1. **Linux Sandboxing:** Landlock e Seccomp restringem acesso a arquivos fora do diretório de scan e bloqueiam chamadas de sistema perigosas.
2. **Scrubbing de Ambiente:** `_dangerous_env_strip.sh` limpa variáveis que poderiam injetar código malicioso no launcher.
3. **Trust Markers:** A variável interna `_RAPTOR_TRUSTED=1` é exportada apenas pelo `bin/raptor` após a higienização do ambiente.
4. **Target Repository Sanity:** `raptor-trust-check` inspeciona repositórios alvos antes de qualquer execução para evitar payloads ocultos em `.opencode/` ou `.claude/`.
