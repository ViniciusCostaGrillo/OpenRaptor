# OpenRaptor — Evolução para Framework Completo de Hacking Ético e Bug Bounty (Kali Linux + OpenCode + Ghidra/REA)

**Data:** 2026-11-12
**Status:** Aprovado para Planejamento (decisões de engenharia fechadas)

---

## 1. Intenção e Motivação ("O Porquê")

O OpenRaptor já possui uma base sólida para análise estática (Semgrep, CodeQL, OpenAnt), fuzzing binário (AFL++), instrumentação dinâmica (Frida), ponte com Ghidra (`packages/ghidra/`) e um núcleo web alpha (`packages/web/`). Porém, no estado atual, ele ainda é fortemente orientado a análise de código-fonte local e mantém resquícios de integração com Claude Code.

O objetivo desta evolução é transformar o OpenRaptor em uma **ferramenta prática e completa de Hacking Ético e Bug Bounty**, executada **100% em Kali Linux** e controlada via **comandos integrados ao OpenCode** (`.opencode/commands/`), cobrindo:
- **Alvos externos** (domínios, subdomínios, aplicações web, APIs e infraestrutura exposta).
- **Apps e APKs** (descompilação, extração de endpoints/segredos e análise de bibliotecas nativas `.so` via **Ghidra / REA MCP**).
- **Ciclo completo real** (não apenas teórico): Reconhecimento → Análise → Ataque/Exploração ética controlada → Defesa/Remediação → Geração de Relatórios prontos para submissão.
- **Comando mestre (`/hunt`)** que classifica o alvo, planeja o fluxo adequado e **solicita confirmação explícita do operador antes de cada ação**.

---

## 2. Objetivos, Não-Objetivos e Anti-Objetivos

### Objetivos
1. **Comando Mestre `/hunt`:** Ponto de entrada único no OpenCode (e CLI `python3 raptor.py hunt`) capaz de inspecionar o alvo (domínio/URL, IP/CIDR, APK/IPA/binário ou repositório) e propor o próximo passo de forma interativa.
2. **Confirmação Passo a Passo (Human-in-the-Loop):** Nenhuma `ActionProposal` (passiva, local, ativa ou intrusiva) é executada sem apresentar ao operador o comando exato, o alvo, o nível de risco e aguardar aprovação.
3. **Guardião de Escopo Rígido (`Scope Guard`):** Suporte a `in-scope` / `out-of-scope` (wildcards de domínio, URLs, CIDRs), rate limiting e headers customizados de Bug Bounty (ex.: `X-Bug-Bounty`, cookies/tokens de sessão) aplicados de forma determinística antes de qualquer execução.
4. **Pipeline de Reconhecimento & Superfície de Ataque (Kali):** Integração estruturada com ferramentas padrão do Kali Linux (`subfinder`, `httpx`, `nmap`, `katana`, `ffuf`, `nuclei`).
5. **Exploração Ética Ativa:** Ativar os adaptadores hoje marcados como `planned` em `packages/web/tool_adapters.py` (`dalfox`, `sqlmap`) e expandir `packages/exploitation/` para validação prática controlada com captura de evidências (request/response/diff/PoC).
6. **Pipeline Mobile/APK + Ghidra/REA:** Extração e análise estática de APKs (`apktool`/`jadx`, busca de segredos, endpoints e permissões inseguras) conectada à análise de binários nativos `.so` via `packages/ghidra/` e servidor MCP **REA**.
7. **Relatórios Profissionais (Ataque + Defesa):** Geração de relatórios em Markdown e HTML prontos para **Bug Bounty** (formato HackerOne/Bugcrowd: título, severidade CVSS, passos de reprodução/PoC, evidências, impacto e remediação) e **Pentest** (sumário executivo + detalhamento técnico).
8. **Padronização OpenCode + Kali Linux:** Alinhar `bin/raptor`, `install.sh`, `setup-kali.sh` e `.opencode/commands/` para operar nativamente com OpenCode no Kali Linux, sem depender de fluxos legados do Claude Code.

### Não-Objetivos
- Não construir um scanner proprietário para substituir ferramentas consagradas do Kali (`nmap`, `nuclei`, `sqlmap`, `dalfox`, `jadx`) — o foco é orquestração, controle de escopo, correlação e evidência.
- Não criar uma GUI web própria; a interface principal é o terminal no Kali Linux + OpenCode.
- Não implementar modo "100% autônomo sem confirmação" para exploração externa (o operador explicitamente exige confirmação antes de cada ação).

### Anti-Objetivos (o que tornaria o projeto um fracasso)
- **Vazamento de escopo:** disparar tráfego para domínios/IPs fora do escopo autorizado de Bug Bounty.
- **Execução silenciosa:** rodar comandos ofensivos ou intrusivos sem mostrar o comando e pedir confirmação antes.
- **Relatórios genéricos sem PoC:** gerar apenas listas de alertas teóricos sem evidência reproduzível (request/response, payload, saída de ferramenta).

---

## 3. Restrições Técnicas e Operacionais

- **Ambiente:** 100% Kali Linux (`apt`, ferramentas de segurança nativas no `PATH`), Python 3.12+ gerenciado via `uv` (`.venv`).
- **Interface de Agente:** OpenCode (`.opencode/commands/*.md`, `opencode.json`).
- **Engenharia Reversa:** Ghidra headless / `pyghidra` (`packages/ghidra/`) e servidor MCP **REA** quando disponível no ambiente.
- **Segurança de Execução:** Manter compatibilidade com `core/run/` (`start_run`, `complete_run`, `fail_run`, `OUTPUT_DIR`) e regras de execução do `AGENTS.md` (sem interpolação insegura em shell).

---

## 4. Abordagens Consideradas

| Abordagem | Descrição | Trade-offs | Decisão |
|---|---|---|---|
| **1. 100% Pacotes Python Rígidos** | Todas as ferramentas do Kali encapsuladas em wrappers/parsers Python obrigatórios. | Alta previsibilidade, mas lento para adicionar novas ferramentas ou análises ad-hoc. | Descartada |
| **2. Apenas Prompts/Skills OpenCode** | `/hunt` como prompt puro em `.opencode/commands/hunt.md` chamando `bash` diretamente. | Rápido de criar, mas sem trava determinística de escopo, sem parsers estruturados nem relatório confiável. | Descartada |
| **3. Híbrida (Backbone Python + Execução Flexível OpenCode/REA)** | Núcleo determinístico em Python para Escopo, Recon/Web/APK core, Registro de Evidências e Relatórios; execução interativa flexível via OpenCode + REA MCP sob a mesma fila de confirmação e diretório de evidências. | Combina segurança determinística (escopo, evidência, CVSS, relatório) com agilidade para ferramentas do Kali e RE interativa no REA/Ghidra. | **Selecionada** |

---

## 5. Arquitetura e Componentes da Solução (Abordagem 3)

### 5.1. Guardião de Escopo e Classificador de Alvo (`packages/hunt/`)
- **`scope.py`:** Lê e valida `<projeto>/scope.json` (ou flags CLI `--scope`, `--out-of-scope`, `--rate-limit`, `--header`). Toda URL, host ou IP antes de ser passado a qualquer runner passa por `assert_in_scope(target)`. Bloqueia imediatamente alvos fora do escopo ou IPs privados não autorizados.
- **`classifier.py`:** Detecta automaticamente o tipo de alvo passado ao `/hunt`:
  - `external_domain` / `url` / `ip_cidr` → fluxo Recon + Web/API/Infra.
  - `apk` / `ipa` / `mobile_app` → fluxo Mobile + Extração de Endpoints/Segredos + Ghidra/REA para `.so`.
  - `binary` → fluxo RE/Fuzzing (`packages/ghidra/` + `packages/binary_analysis/` + AFL++ + REA).
  - `repo` → fluxo SAST/Audit existente (`/agentic`, `/scan`, `/understand`).
- **`planner.py`:** Gera o plano de próxima ação em etapas discretas (`ActionProposal`: `id`, `phase`, `tool`, `command_preview`, `risk_level`, `expected_evidence`). No modo interativo (padrão obrigatório), **nenhuma `ActionProposal` é executada sem confirmação explícita do operador**.
- **`evidence_store.py`:** Contrato único em `OUTPUT_DIR/evidence/` (`findings.json`, `raw_outputs/`, `http_traces/`) onde tanto os runners Python quanto comandos ad-hoc aprovados no OpenCode/REA registram achados estruturados para o relatório final.

### 5.2. Pipeline de Reconhecimento & Web/API Ativo (`packages/hunt/recon.py` + `packages/web/`)
- **Reconhecimento externo (Kali):** Wrappers com parsers estruturados (JSON/XML) para:
  - `subfinder` (enumeração passiva de subdomínios)
  - `httpx` (probe HTTP, status, tecnologias, títulos, redirecionamentos)
  - `nmap` (scan de portas/serviços com saída `-oX` parseada)
  - `katana` (crawling moderno complementar ao `packages/web/crawler.py`)
- **Web/API Ativo (`packages/web/tool_adapters.py` e `packages/exploitation/`):**
  - Promover `dalfox` (XSS) e `sqlmap` (SQLi) de `execution="planned"` para `execution="external"` com parsers estruturados e gate obrigatório de confirmação prévia.
  - Integrar `nuclei` (`-jsonl`) e `ffuf` ao mesmo `Scope Guard` e propagação de headers/cookies de Bug Bounty.
  - Expandir `packages/exploitation/` com suporte a geração de PoCs reproduzíveis (`curl`, scripts Python, HTTP raw request/response) vinculados aos achados validados.

### 5.3. Pipeline Mobile / APK + Ghidra / REA (`packages/mobile/` + `packages/ghidra/`)
- **`apk_analyzer.py`:** Orquestra `apktool` e `jadx` (quando presentes no Kali) para:
  - Analisar `AndroidManifest.xml` (atividades/services/receivers exportados, `debuggable`, `allowBackup`, deep links).
  - Extrair URLs, endpoints de API, chaves/tokens hardcoded e pinning de certificado.
  - Listar bibliotecas nativas (`lib/<abi>/*.so`).
- **Integração Ghidra / REA:**
  - Conectar automaticamente os `.so` extraídos ao fluxo de `packages/ghidra/` (`headless.py` / `bridge.py`) para decompilação e busca de funções sensíveis (`strcpy`, `system`, criptografia hardcoded, validação de licença/assinatura).
  - Documentar e integrar no `/hunt` e `/ghidra` o fluxo assistido pelo **REA MCP** para análise interativa profunda (inspeção de símbolos, decompilação sob demanda, correlação estática/dinâmica com Frida).

### 5.4. Motor de Relatórios Bug Bounty & Pentest (`core/reporting/bounty_report.py`)
- Consome `evidence_store.py` + achados de `core/reporting/findings.py` e gera:
  - **Bug Bounty Report (`bounty-report.md`):** Pronto para copiar/colar no HackerOne/Bugcrowd (Título, CWE, Severidade + vetor CVSS, Asset em Escopo, Descrição, Passos para Reprodução com `curl`/PoC, Evidência Request/Response, Impacto e Recomendação de Correção).
  - **Pentest Report (`pentest-report.md` e `pentest-report.html`):** Sumário executivo, mapa da superfície de ataque descoberta, tabela de achados por severidade, detalhamento técnico ofensivo e plano de remediação defensivo.

### 5.5. Comandos OpenCode e Padronização Kali (`bin/raptor`, `.opencode/commands/`, `setup-kali.sh`)
- **Novos comandos OpenCode:**
  - `/hunt <alvo>` — Comando mestre interativo (classifica alvo, configura/verifica escopo, propõe e confirma cada ação).
  - `/recon <alvo>` — Reconhecimento externo focado (subdomínios, portas, HTTP probe, crawling).
  - `/mobile <apk>` — Análise de APK + extração para Ghidra/REA.
  - `/report <out-dir>` — Geração de relatório Bug Bounty / Pentest a partir das evidências coletadas.
- **Limpeza OpenCode + Kali:**
  - Atualizar `bin/raptor` para remover textos e fluxos residuais que assumem Claude Code como primário, priorizando OpenCode.
  - Atualizar `setup-kali.sh` / `install.sh` para verificar e instalar (com confirmação/apt/go/uv) a suíte recomendada de ferramentas no Kali (`nmap`, `subfinder`, `httpx`, `katana`, `nuclei`, `ffuf`, `dalfox`, `sqlmap`, `apktool`, `jadx`, `ghidra`).

---

## 6. Decisões de Engenharia Fechadas (Pós-Builder Check)

1. **Escopo em comandos ad-hoc vs. runners Python:** Todos os runners Python (`subfinder`, `httpx`, `nmap`, `katana`, `ffuf`, `nuclei`, `dalfox`, `sqlmap`) aplicam `packages/hunt/scope.py` de forma determinística. Comandos ad-hoc sugeridos pelo agente OpenCode/REA passam obrigatoriamente pela confirmação no chat (exibindo comando, alvo e risco) antes de rodar, mantendo a arquitetura enxuta sem proxy de rede no OS nesta fase.
2. **Máquina de estados sem bloqueio de `stdin`:** `packages/hunt/planner.py` opera como máquina de estados persistida em disco (`plan-next` → grava `ActionProposal` pendente em `OUTPUT_DIR/hunt_state.json` → operador aprova no OpenCode → `execute --approved <id>`), evitando `input()` bloqueante dentro da tool `bash` do OpenCode. Um loop CLI interativo opcional (`--interactive`) pode envolver essa mesma máquina de estados.
3. **Isolamento de `scope.py` e bloqueio de IPs privados:** `packages/hunt/scope.py` é independente de `packages/web/execution_policy.py` (`ScopeReceipt`) para não quebrar contratos/testes existentes de `/web`, adaptando origens concretas quando delegar ao `/web`. `scope.py` suporta wildcards (`*.alvo.com`), CIDRs, lista `out_of_scope`, headers/cookies de Bug Bounty e resolução DNS para bloquear IPs privados/loopback/link-local por padrão (a menos que explicitamente autorizados no `scope.json`).
4. **Confirmação universal:** Todas as `ActionProposal`s (incluindo recon passivo, análise estática local e ações ativas/intrusivas) exigem confirmação explícita antes da execução.
5. **OpenCode + Kali como padrão preservando fallbacks:** `bin/raptor`, `install.sh` e `setup-kali.sh` priorizam OpenCode e ferramentas do Kali Linux, mantendo fallbacks legados apenas onde não atrapalham o fluxo principal (evitando quebra de testes existentes).
6. **REA MCP condicional:** O servidor MCP REA é assumido como provisionado pelo operador no ambiente; `.opencode/commands/hunt.md` e `ghidra.md` o orquestram quando disponível e fazem fallback automático para `packages/ghidra/` (`analyzeHeadless`/`pyghidra`) + `packages/frida/`.
7. **Escopo Mobile nesta entrega:** Pipeline focado em **Android `.apk`** (`apktool`, `jadx`, `AndroidManifest.xml`, segredos/endpoints e `lib/<abi>/*.so` via Ghidra/REA). `.ipa` é reconhecido pelo classificador como alvo futuro sem pipeline iOS dedicado nesta fase.

---

## 7. O que Fica a Cargo da Etapa de Planejamento/Implementação (Builder)
- Definição exata dos schemas Pydantic/JSON de `scope.json`, `ActionProposal` e `evidence_store`.
- Escolha das bibliotecas Python auxiliares (ex.: Jinja2, já instalada no `.venv`, para templates HTML de relatório).
- Escrita dos testes unitários com mocks de saída das ferramentas externas (`nmap` XML, `nuclei` JSONL, `subfinder`/`httpx` JSON, `dalfox`, `sqlmap`, `apktool`).
- Sequenciamento das entregas em fases incrementais testáveis via `pytest`, `ruff` e `mypy`.
