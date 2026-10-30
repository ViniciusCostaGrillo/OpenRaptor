# Mapeamento de Comandos e Subagentes — OpenCode

## 1. Mapeamento dos 39 Slash Commands

Todos os 39 comandos originais do RAPTOR foram catalogados e mapeados para `.opencode/commands/*.md`.

| Comando | Descrição Operacional | Despacho Executável |
| :--- | :--- | :--- |
| `/raptor` | Ponto de entrada interativo principal | `bin/raptor` |
| `/agentic` | Pipeline autônomo completo (Scan -> Dedup -> Validação -> Patch) | `libexec/raptor-agentic --repo $ARGUMENTS` |
| `/scan` | Análise estática com Semgrep e Coccinelle | `python3 raptor.py scan $ARGUMENTS` |
| `/fuzz` | Fuzzing de binários com AFL++ e análise de crash | `python3 raptor.py fuzz $ARGUMENTS` |
| `/web` | Varredura de aplicações web com oráculos de injeção | `python3 raptor.py web $ARGUMENTS` |
| `/codeql` | Análise semântica profunda via CodeQL | `python3 raptor.py codeql $ARGUMENTS` |
| `/analyze` | Análise LLM de resultados SARIF existentes | `python3 raptor.py analyze $ARGUMENTS` |
| `/audit` | Auditoria de código orientada a hipóteses com verificação determinística | `libexec/raptor-audit $ARGUMENTS` |
| `/understand` | Mapeamento de superfície de ataque, fluxo de dados e grafos | `libexec/raptor-understand $ARGUMENTS` |
| `/validate` | Pipeline de validação de explorabilidade em estágios (0, A-F, 1) | `skills/exploitability-validation` |
| `/exploit` | Geração de código de prova de conceito (PoC) | `python3 raptor.py agentic $ARGUMENTS` |
| `/patch` | Geração de correções seguras para vulnerabilidades confirmadas | `python3 raptor.py agentic $ARGUMENTS` |
| `/binary` | Investigação de binários black-box (grafo SQLite e XREFs) | `libexec/raptor-binary $ARGUMENTS` |
| `/ghidra` | Bridge com Ghidra para projetos descompilados | `libexec/raptor-ghidra $ARGUMENTS` |
| `/sca` | Análise de composição de software e dependências | `python3 raptor.py sca $ARGUMENTS` |
| `/cve-diff` | Busca e comparação do commit de correção de uma CVE | `libexec/raptor-cve-diff $ARGUMENTS` |
| `/cve-env` | Criação e verificação de ambiente Docker para uma CVE | `libexec/raptor-cve-env $ARGUMENTS` |
| `/describe` | Inspeção prévia do alvo: linguagem, build system e custos | `libexec/raptor-describe $ARGUMENTS` |
| `/threat-model` | Criação, inspeção e manutenção de modelos de ameaça | `libexec/raptor-threat-model $ARGUMENTS` |
| `/diagram` | Geração de diagramas Mermaid visuais a partir de saídas JSON | `libexec/raptor-render-diagrams $ARGUMENTS` |
| `/project` | Gerenciamento de workspaces e projetos ativos | `libexec/raptor-project-manager $ARGUMENTS` |
| `/review` | Consulta do estado de auditoria: gaps, cobertura e notas | `libexec/raptor-review $ARGUMENTS` |
| `/annotate` | Inserção de anotações de revisão por função | `libexec/raptor-annotate $ARGUMENTS` |
| `/sage` | Camada de memória persistente vetorial | `libexec/raptor-sage $ARGUMENTS` |
| `/ask` | Envio de prompts diretos para qualquer modelo LLM | `libexec/raptor-llm-ask $ARGUMENTS` |
| `/openant` | Scan semântico via AST e análise per-function | `libexec/raptor-openant $ARGUMENTS` |
| `/crash-analysis`| Análise autônoma de root-cause de crashes C/C++ via GDB/ASAN | `libexec/raptor-study-run $ARGUMENTS` |
| `/scorecard` | Avaliação comparativa de precisão entre modelos | `libexec/raptor-llm-scorecard $ARGUMENTS` |
| `/oss-forensics` | Investigação forense de repositórios GitHub com evidências | `skills/oss-forensics` |
| `/tune` | Ajuste de perfis de desempenho e limites de recursos | `libexec/raptor-tune $ARGUMENTS` |
| `/frida` | Instrumentação dinâmica em tempo de execução via Frida | `libexec/raptor-frida $ARGUMENTS` |
| `/commands` | Listagem interativa de comandos disponíveis | Visualização de tabela |
| `/create-skill` | Salvamento de abordagens e procedimentos aprendidos | Criação de novo skill |
| `/gadget-scan` | Varredura de gadgets de exploração em binários | `libexec/raptor-gadget-scan $ARGUMENTS` |
| `/may-ask` | Consulta sobre limites de interação com operador | `libexec/raptor-may-ask $ARGUMENTS` |
| `/sandbox` | Diagnóstico e telemetria de sandboxes Landlock/Seccomp | `libexec/raptor-sandbox-summary $ARGUMENTS` |
| `/seatbelt` | Verificação de restrições de contenção de processo | `libexec/raptor-seatbelt-shim $ARGUMENTS` |
| `/self-test` | Bateria de autotestes de sanidade do RAPTOR | `libexec/raptor-self-test $ARGUMENTS` |
| `/version` | Exibição da versão atual do framework | `python3 raptor.py --version` |

---

## 2. Mapeamento de Subagentes Especialistas

Localizados em `.opencode/agents/*.md`, configurados com `mode: subagent`:

1. **`exploitability-validator-agent.md`**: Especialista em validação em estágios para evitar falsos positivos antes do desenvolvimento de exploits.
2. **`offsec-specialist.md`**: Especialista ofensivo focado em rotas de exploração, bypasses e geração de PoCs.
3. **`audit-reviewer.md`**: Especialista em revisão de auditoria e cobertura de código.
4. **`crash-analysis-agent.md`**: Especialista em análise de memória, registradores e rastros de crashes.
5. **Agentes Forenses OSS**:
   - `oss-evidence-verifier-agent.md`
   - `oss-hypothesis-former-agent.md`
   - `oss-hypothesis-checker-agent.md`
   - `oss-investigator-local-git-agent.md`
   - `oss-investigator-github-agent.md`
   - `oss-report-generator-agent.md`
