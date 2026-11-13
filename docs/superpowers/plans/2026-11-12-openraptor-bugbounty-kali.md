# OpenRaptor Bug Bounty & Ethical Hacking (Kali + OpenCode + Ghidra/REA) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evoluir o OpenRaptor para um framework prático e completo de Hacking Ético e Bug Bounty rodando 100% em Kali Linux via OpenCode, com comando mestre `/hunt`, trava rígida de escopo, confirmação passo a passo antes de cada ação, recon externo, exploração web ativa, pipeline APK + Ghidra/REA e relatórios profissionais.

**Architecture:** Arquitetura híbrida (Abordagem 3 da spec): um backbone determinístico em Python (`packages/hunt/`, `packages/mobile/`, `packages/web/`, `packages/exploitation/`, `core/reporting/`) garante validação rígida de escopo, máquina de estados resumível para aprovação humana sem bloquear `stdin`, parsers estruturados das ferramentas do Kali e geração de relatórios HackerOne/Bugcrowd/Pentest. A camada OpenCode (`.opencode/commands/`) e o launcher (`bin/raptor`, `setup-kali.sh`) orquestram esse backbone e análises interativas no REA MCP com fallback automático para `packages/ghidra/` + `packages/frida/`.

**Tech Stack:** Python 3.12+, Pydantic, Jinja2, `uv`, `pytest`, `ruff`, `mypy`; ferramentas Kali Linux (`subfinder`, `httpx`, `nmap`, `katana`, `ffuf`, `nuclei`, `dalfox`, `sqlmap`, `apktool`, `jadx`, `ghidra`); OpenCode CLI + REA MCP.

**Spec:** [2026-11-12-openraptor-bugbounty-kali-design.md](file:///c:/OpenRaptor/docs/superpowers/specs/2026-11-12-openraptor-bugbounty-kali-design.md)

## Global Constraints

- Ambiente-alvo 100% Kali Linux (`apt` + ferramentas no `PATH`), Python 3.12+ gerenciado por `uv` (`.venv`).
- Nenhuma `ActionProposal` (passiva, local, ativa ou intrusiva) pode ser executada sem confirmação explícita prévia do operador.
- Máquina de estados persistida em disco (`hunt_state.json`) sem uso de `input()` bloqueante no fluxo acionado pelo OpenCode.
- Nenhum runner externo pode disparar tráfego sem validação prévia por `packages/hunt/scope.py` (`assert_in_scope`), bloqueando `out_of_scope` e IPs privados/loopback não autorizados.
- Manter contratos e testes existentes de `packages/web/execution_policy.py` (`ScopeReceipt`) intactos; `packages/hunt/scope.py` vive isolado em `packages/hunt/`.
- Preservar compatibilidade com `core/run/` (`start_run`, `complete_run`, `fail_run`, `OUTPUT_DIR`) e regras do `AGENTS.md` (sem shell interpolation insegura).

## Review Focus

- **Wildcard & Subdomain Edge Cases:** `*.example.com` deve aceitar `api.example.com`, rejeitar `badexample.com`, rejeitar `example.com` se não listado explicitamente, e respeitar `out_of_scope` mesmo se um subdomínio casar com o wildcard `in_scope`.
- **DNS Rebinding / Private IP SSRF:** Um domínio `in_scope` que resolve via DNS para `127.0.0.1`, `10.0.0.0/8`, `169.254.169.254` ou `::1` deve ser bloqueado por `assert_in_scope` quando `allow_private_ips=False`.
- **Blocked/Unapproved Action Execution:** Tentar chamar `execute_action(state_path, action_id)` sem aprovação explícita gravada no estado deve levantar `PermissionError` e nunca invocar `subprocess`.
- **Malformed External Tool Output:** XML truncado do `nmap`, JSONL inválido do `nuclei`/`httpx` ou ausência do binário no `PATH` devem retornar erro estruturado (ou status `tool_missing`) sem crashar o pipeline nem perder evidências já coletadas.
- **APK Path Traversal (Zip Slip) & Missing `.so`:** APKs sem bibliotecas nativas ou com entradas maliciosas no zip não devem quebrar o pipeline; devem gerar achados de `AndroidManifest.xml`/segredos normalmente e registrar que não há `.so` para o Ghidra.

---

### Task 1: Scope Guard e Target Classifier (`packages/hunt/scope.py`, `packages/hunt/classifier.py`)

**Files:**
- Create: `packages/hunt/__init__.py`
- Create: `packages/hunt/scope.py`
- Create: `packages/hunt/classifier.py`
- Test: `packages/hunt/tests/test_scope_and_classifier.py`

**Interfaces:**
- Consumes: `ipaddress`, `socket`, `fnmatch`, `urllib.parse`, `pydantic`
- Produces:
  - `ScopeConfig` (Pydantic model: `in_scope: list[str]`, `out_of_scope: list[str]`, `rate_limit_rps: float`, `headers: dict[str, str]`, `cookies: dict[str, str]`, `allow_private_ips: bool = False`)
  - `ScopeViolationError(Exception)`
  - `assert_in_scope(target: str, config: ScopeConfig, *, resolve_dns: bool = True) -> str`
  - `TargetKind` (`Literal["external_domain", "url", "ip_cidr", "apk", "binary", "repo", "ipa"]`)
  - `classify_target(target: str) -> TargetClassification`

- [ ] **Step 1: Write the failing tests for Scope Guard and Target Classifier**

Create `packages/hunt/tests/test_scope_and_classifier.py` covering:
- Wildcard match (`*.example.com` accepts `app.example.com`, rejects `evil-example.com`).
- `out_of_scope` precedence (`admin.example.com` rejected even if `*.example.com` is in `in_scope`).
- Private IP blocking (`127.0.0.1`, `10.1.2.3`, `169.254.169.254` rejected when `allow_private_ips=False`, including mocked DNS resolution of `internal.example.com -> 127.0.0.1`).
- CIDR matching (`192.0.2.0/24` accepts `192.0.2.15`, rejects `192.0.3.1`).
- `classify_target` for `https://target.com`, `target.com`, `203.0.113.0/24`, `app.apk`, `app.ipa`, local directory (repo), and ELF binary file.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest packages/hunt/tests/test_scope_and_classifier.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'packages.hunt'`

- [ ] **Step 3: Implement `packages/hunt/__init__.py`, `packages/hunt/scope.py`, and `packages/hunt/classifier.py`**

Implement:
- `ScopeConfig.from_file(path)` and `ScopeConfig.from_target(target)` (auto-generates safe single-target scope when no `scope.json` is provided).
- `assert_in_scope(target, config, resolve_dns=True)`: parses URL/host/IP/CIDR, checks `out_of_scope` first, checks `in_scope` (exact host, `*.domain` suffix, CIDR), resolves DNS via `socket.getaddrinfo` when `resolve_dns=True` and rejects private/loopback/link-local/reserved IPs unless `config.allow_private_ips=True`.
- `classify_target(target)` checking filesystem paths (`apk`, `ipa`, directory/repo, ELF/PE binary) vs network targets (`url`, `ip_cidr`, `external_domain`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest packages/hunt/tests/test_scope_and_classifier.py -v`
Expected: PASS (all tests green)

- [ ] **Step 5: Commit**

Run: `git add packages/hunt/__init__.py packages/hunt/scope.py packages/hunt/classifier.py packages/hunt/tests/test_scope_and_classifier.py && git commit -m "feat(hunt): add scope guard and target classifier"`

---

### Task 2: Resumable Action Planner & Evidence Store (`packages/hunt/planner.py`, `packages/hunt/evidence_store.py`)

**Files:**
- Create: `packages/hunt/planner.py`
- Create: `packages/hunt/evidence_store.py`
- Test: `packages/hunt/tests/test_planner_and_evidence.py`

**Interfaces:**
- Consumes: `ScopeConfig`, `TargetClassification` (from Task 1), `core.run.safe_io`
- Produces:
  - `ActionProposal` (`id`, `phase`, `tool`, `target`, `command_preview`, `risk_level`, `expected_evidence`, `status`: `pending | approved | rejected | executed | failed`)
  - `HuntSessionState` (persisted at `OUTPUT_DIR/hunt_state.json`)
  - `init_hunt_session(out_dir: Path, target: str, scope: ScopeConfig) -> HuntSessionState`
  - `propose_next_action(out_dir: Path) -> ActionProposal | None`
  - `approve_action(out_dir: Path, action_id: str) -> ActionProposal`
  - `reject_action(out_dir: Path, action_id: str, reason: str = "") -> ActionProposal`
  - `require_approved_action(out_dir: Path, action_id: str) -> ActionProposal` (raises `PermissionError` if not `approved`)
  - `EvidenceStore(out_dir: Path)` with `record_finding(...)`, `record_raw_output(...)`, `record_http_trace(...)`, `load_findings() -> list[dict]`

- [ ] **Step 1: Write the failing tests**

Create `packages/hunt/tests/test_planner_and_evidence.py` covering:
- `init_hunt_session` creates `hunt_state.json` and `propose_next_action` yields phase-ordered `ActionProposal`s for `external_domain`, `url`, and `apk`.
- `require_approved_action` raises `PermissionError` when `status == "pending"` or `"rejected"`, and succeeds only after `approve_action`.
- State persists across reloads from disk (simulating separate OpenCode turns).
- `EvidenceStore` writes `findings.json`, `raw_outputs/<id>.txt`, and `http_traces/<id>.json` atomically and deduplicates by `(title, target, vuln_type)`.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest packages/hunt/tests/test_planner_and_evidence.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `packages/hunt/planner.py` and `packages/hunt/evidence_store.py`**

Implement disk-persisted state machine (`hunt_state.json`) and `EvidenceStore` (`OUTPUT_DIR/evidence/`). Ensure no `input()` calls exist inside `planner.py` core functions.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest packages/hunt/tests/test_planner_and_evidence.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

Run: `git add packages/hunt/planner.py packages/hunt/evidence_store.py packages/hunt/tests/test_planner_and_evidence.py && git commit -m "feat(hunt): add resumable action planner and evidence store"`

---

### Task 3: Kali Recon Runners & Parsers (`packages/hunt/recon.py`)

**Files:**
- Create: `packages/hunt/recon.py`
- Test: `packages/hunt/tests/test_recon.py`

**Interfaces:**
- Consumes: `assert_in_scope`, `ScopeConfig`, `EvidenceStore`
- Produces:
  - `run_subfinder(domain: str, scope: ScopeConfig, out_dir: Path) -> ReconResult`
  - `run_httpx(targets: list[str], scope: ScopeConfig, out_dir: Path) -> ReconResult`
  - `run_nmap(target: str, scope: ScopeConfig, out_dir: Path, *, ports: str = "--top-ports 1000") -> ReconResult`
  - `run_katana(url: str, scope: ScopeConfig, out_dir: Path, *, depth: int = 3) -> ReconResult`
  - `parse_nmap_xml(xml_text: str) -> list[dict]` (using `defusedxml.ElementTree`)

- [ ] **Step 1: Write the failing tests**

Create `packages/hunt/tests/test_recon.py` with mocked `subprocess.run` and `shutil.which` covering:
- `subfinder` JSON lines parsing + filtering discovered subdomains through `assert_in_scope(..., resolve_dns=False)` so out-of-scope subdomains are dropped.
- `httpx` JSON lines parsing (URL, status code, tech stack, title, header propagation from `ScopeConfig`).
- `nmap` XML parsing via `defusedxml` (hosts, open ports, service, version) and graceful handling of truncated XML.
- `katana` URL/endpoint extraction filtered by `ScopeConfig`.
- Missing binary returns `status="tool_missing"` without raising unhandled exception.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest packages/hunt/tests/test_recon.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `packages/hunt/recon.py`**

Implement runners using `subprocess.run(..., shell=False)` with list-form argv, `ScopeConfig` validation before execution, `defusedxml` for `nmap` XML, and automatic persistence to `EvidenceStore`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest packages/hunt/tests/test_recon.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

Run: `git add packages/hunt/recon.py packages/hunt/tests/test_recon.py && git commit -m "feat(hunt): add Kali recon runners and parsers (subfinder, httpx, nmap, katana)"`

---

### Task 4: Active Web Adapters (`dalfox`, `sqlmap`) & PoC Generation (`packages/web/`, `packages/exploitation/`)

**Files:**
- Modify: `packages/web/tool_adapters.py:103-127`
- Create: `packages/web/external_runners.py`
- Create: `packages/exploitation/poc_generator.py`
- Test: `packages/web/tests/test_external_runners.py`
- Test: `packages/exploitation/tests/test_poc_generator.py`

**Interfaces:**
- Consumes: `ScopeConfig`, `assert_in_scope`, `EvidenceStore`, `packages/web/tool_adapters.py`
- Produces:
  - `dalfox` and `sqlmap` promoted to `execution="external"`, `parser_status="structured"` in `packages/web/tool_adapters.py`
  - `run_dalfox(url: str, scope: ScopeConfig, out_dir: Path, *, approved: bool) -> list[dict]`
  - `run_sqlmap(url: str, scope: ScopeConfig, out_dir: Path, *, approved: bool, data: str | None = None) -> list[dict]`
  - `generate_http_poc(finding: dict) -> str` (generates reproducible `curl` command + Python `requests` PoC snippet)

- [ ] **Step 1: Write the failing tests**

Create `packages/web/tests/test_external_runners.py` and `packages/exploitation/tests/test_poc_generator.py` covering:
- `run_dalfox` and `run_sqlmap` raise `PermissionError` if `approved=False` and raise `ScopeViolationError` if URL is out of scope.
- `run_dalfox` parses JSON output into normalized XSS findings.
- `run_sqlmap` runs non-interactively (`--batch --answers=...`) and parses injection technique/parameter/DBMS evidence.
- `web_tool_adapter("dalfox").execution == "external"` and `web_tool_adapter("sqlmap").execution == "external"`.
- `generate_http_poc` outputs valid `curl` and `requests` reproduction snippets from `http_trace` evidence.

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python.exe -m pytest packages/web/tests/test_external_runners.py packages/exploitation/tests/test_poc_generator.py -v`
Expected: FAIL

- [ ] **Step 3: Implement adapters, runners, and PoC generator**

Update `packages/web/tool_adapters.py`, create `packages/web/external_runners.py` and `packages/exploitation/poc_generator.py`.

- [ ] **Step 4: Run tests and existing web/exploitation tests**

Run: `.venv\Scripts\python.exe -m pytest packages/web/tests/test_external_runners.py packages/exploitation/tests/test_poc_generator.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

Run: `git add packages/web/tool_adapters.py packages/web/external_runners.py packages/exploitation/poc_generator.py packages/web/tests/test_external_runners.py packages/exploitation/tests/test_poc_generator.py && git commit -m "feat(web,exploitation): enable dalfox/sqlmap runners with approval gate and PoC generator"`

---

### Task 5: Pipeline Mobile APK + Ghidra/REA Bridge (`packages/mobile/apk_analyzer.py`)

**Files:**
- Create: `packages/mobile/__init__.py`
- Create: `packages/mobile/apk_analyzer.py`
- Test: `packages/mobile/tests/test_apk_analyzer.py`

**Interfaces:**
- Consumes: `defusedxml.ElementTree`, `zipfile`, `packages/ghidra/headless.py` (optional handoff)
- Produces:
  - `ApkAnalysisResult` (`package_name`, `exported_components`, `manifest_flags`, `endpoints`, `secrets`, `native_libs`, `ghidra_targets`)
  - `analyze_apk(apk_path: Path, out_dir: Path, *, run_jadx: bool = True, run_apktool: bool = True) -> ApkAnalysisResult`
  - `parse_android_manifest(manifest_xml: str) -> dict`

- [ ] **Step 1: Write the failing tests**

Create `packages/mobile/tests/test_apk_analyzer.py` covering:
- Parsing `AndroidManifest.xml` for `android:debuggable="true"`, `android:allowBackup="true"`, `usesCleartextTraffic="true"`, and exported activities/services/receivers without permissions.
- Safe extraction of `.so` files from a synthetic `.apk` (zip) while rejecting zip-slip paths (`../../evil`).
- Scanning extracted source/strings for hardcoded API URLs and AWS/Firebase/Generic Bearer tokens.
- Graceful handling when APK has zero `.so` files or when `jadx`/`apktool` are absent.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest packages/mobile/tests/test_apk_analyzer.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `packages/mobile/__init__.py` and `packages/mobile/apk_analyzer.py`**

Implement safe zip extraction, `defusedxml` manifest parser, regex-based endpoint/secret scanner, `.so` discovery, and optional handoff list for `packages/ghidra` / REA MCP.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest packages/mobile/tests/test_apk_analyzer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

Run: `git add packages/mobile/__init__.py packages/mobile/apk_analyzer.py packages/mobile/tests/test_apk_analyzer.py && git commit -m "feat(mobile): add Android APK analyzer and Ghidra native lib handoff"`

---

### Task 6: Bug Bounty & Pentest Report Generator (`core/reporting/bounty_report.py`)

**Files:**
- Create: `core/reporting/bounty_report.py`
- Test: `core/reporting/tests/test_bounty_report.py`

**Interfaces:**
- Consumes: `EvidenceStore` (`findings.json`), `jinja2`, `core.security.prompt_output_sanitise`
- Produces:
  - `generate_bounty_reports(out_dir: Path, *, target: str, platform: str = "generic") -> dict[str, Path]` (writes `bounty-report.md`, `pentest-report.md`, `pentest-report.html`)

- [ ] **Step 1: Write the failing tests**

Create `core/reporting/tests/test_bounty_report.py` covering:
- Generating `bounty-report.md` with HackerOne/Bugcrowd structure (Title, CWE, CVSS/Severity, Asset, Steps to Reproduce + `curl` PoC, Request/Response Evidence, Impact, Remediation).
- Generating `pentest-report.md` and `pentest-report.html` with executive summary counts by severity and HTML escaping of untrusted payload strings (no raw XSS in generated HTML report).
- Handling empty findings list cleanly ("No confirmed vulnerabilities").

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest core/reporting/tests/test_bounty_report.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `core/reporting/bounty_report.py`**

Implement Markdown and Jinja2 HTML (`autoescape=True`) report generation reading from `OUTPUT_DIR/evidence/findings.json`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python.exe -m pytest core/reporting/tests/test_bounty_report.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

Run: `git add core/reporting/bounty_report.py core/reporting/tests/test_bounty_report.py && git commit -m "feat(reporting): add Bug Bounty and Pentest Markdown/HTML report generator"`

---

### Task 7: CLI Dispatch, OpenCode Commands & Kali Setup (`raptor.py`, `libexec/raptor-hunt`, `.opencode/commands/`, `bin/raptor`, `setup-kali.sh`)

**Files:**
- Create: `packages/hunt/cli.py`
- Create: `libexec/raptor-hunt`
- Modify: `raptor.py` (register `hunt`, `recon`, `mobile`, `report` modes)
- Create: `.opencode/commands/hunt.md`
- Create: `.opencode/commands/recon.md`
- Create: `.opencode/commands/mobile.md`
- Create: `.opencode/commands/report.md`
- Modify: `.opencode/commands/commands.md`
- Modify: `bin/raptor` (prioritize OpenCode messaging/flow while keeping fallback)
- Modify: `setup-kali.sh` (add check/install for `subfinder`, `httpx`, `katana`, `nuclei`, `ffuf`, `dalfox`, `sqlmap`, `apktool`, `jadx`)
- Test: `packages/hunt/tests/test_cli.py`

**Interfaces:**
- Consumes: Tasks 1–6
- Produces:
  - `python3 raptor.py hunt --target <target> [--scope scope.json] [plan-next | approve <id> | reject <id> | execute <id> | status]`
  - `python3 raptor.py recon`, `python3 raptor.py mobile`, `python3 raptor.py report`
  - OpenCode slash commands `/hunt`, `/recon`, `/mobile`, `/report`

- [ ] **Step 1: Write the failing CLI tests**

Create `packages/hunt/tests/test_cli.py` testing:
- `python3 raptor.py hunt --help` exits 0 without side effects.
- `packages/hunt/cli.py` subcommands `init`, `plan-next`, `approve`, `execute` (with mocked runner) follow the approval gate end-to-end.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m pytest packages/hunt/tests/test_cli.py -v`
Expected: FAIL

- [ ] **Step 3: Implement CLI, `libexec/raptor-hunt`, `raptor.py` modes, OpenCode commands, and Kali setup updates**

Wire `hunt`, `recon`, `mobile`, `report` into `raptor.py` and `libexec/raptor-hunt`. Author `.opencode/commands/{hunt,recon,mobile,report}.md` enforcing step-by-step confirmation and REA MCP conditional orchestration with `packages/ghidra/` fallback. Update `bin/raptor` help/banner text to reflect OpenCode-first and add Kali tool checks to `setup-kali.sh`.

- [ ] **Step 4: Run full new test suite + `ruff` check**

Run: `.venv\Scripts\python.exe -m pytest packages/hunt/tests/ packages/mobile/tests/ packages/web/tests/test_external_runners.py packages/exploitation/tests/test_poc_generator.py core/reporting/tests/test_bounty_report.py -v`
Run: `.venv\Scripts\python.exe -m ruff check packages/hunt packages/mobile packages/web/external_runners.py packages/exploitation/poc_generator.py core/reporting/bounty_report.py`
Expected: PASS and 0 lint errors.

- [ ] **Step 5: Commit**

Run: `git add packages/hunt/cli.py libexec/raptor-hunt raptor.py .opencode/commands/ bin/raptor setup-kali.sh packages/hunt/tests/test_cli.py && git commit -m "feat(cli,opencode): wire /hunt, /recon, /mobile, /report commands and Kali tooling"`
