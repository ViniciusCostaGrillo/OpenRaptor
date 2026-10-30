# RAPTOR - Autonomous Offensive/Defensive Research Framework (OpenCode Edition)

Safe operations (install, scan, read, generate): DO IT.
Dangerous operations (apply patches, delete, git push): ASK FIRST.

---

## SESSION START

**On first message:**
VERY IMPORTANT: follow these steps in order.
1. Output the RAPTOR startup banner verbatim as a fenced code block (``` with no language tag):
```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║             ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗             ║
║             ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗            ║
║             ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝            ║
║             ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗            ║
║             ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║            ║
║             ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝            ║
║                                                                           ║
║             Autonomous Offensive/Defensive Research Framework             ║
║             OpenCode & Kali Linux Edition                                 ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```
2. On a single line, output "Quick commands:" then list the `/agentic`, `/scan`, `/fuzz`, `/web` commands and note `/commands` for the full list.
3. Check active session project or target from environment (`$RAPTOR_TARGET` or active project in `~/.local/share/raptor/sessions.d/`).

---

## EXECUTION RULES

When a skill, command file, or user message specifies a literal command (`Execute: foo`, a fenced shell block as the action, or "run X"), execute it verbatim using the bash tool. Do not add pipes (`| tail`, `| head`, `| grep`), redirects (`2>&1`, `>/dev/null`), flags (`--verbose`, `-q`), wrappers (`timeout`, `nice`), `cd` prefixes, or env-var prefixes (`VAR=x cmd`). Environment variables like `_RAPTOR_TRUSTED` are already set by the launcher; prepending them changes the command string and breaks permission grants.
RAPTOR pipelines emit progress lines, real-time cost tracking, and the `OUTPUT_DIR=<path>` sentinel that downstream lifecycle steps parse. Truncating or filtering that stream breaks both operator visibility and orchestration.

Never paste operator-, repo-, or target-derived values inside a double-quoted `python3 -c` block (or any double-quoted program text on a shell command line): the shell expands `$(…)` and backticks carried in the pasted value before the interpreter runs. Dynamic values ride as argv data — a `libexec/raptor-*` shim taking them as arguments, or a script file written with the write tool and run with `sys.argv` arguments.

---

## SLASH-COMMAND DISPATCH

When a `/command` fires in OpenCode:
1. OpenCode loads the corresponding command definition from `.opencode/commands/<name>.md`.
2. Operator arguments are passed via `$ARGUMENTS` verbatim to the dispatch command.
3. If the command runs a pipeline, verify `OUTPUT_DIR` and adhere strictly to the run lifecycle.

---

## COMMANDS

/project - Project management — `libexec/raptor-project-manager <subcommand> [args]`
/scan /fuzz /web /codeql /analyze - Security testing — `python3 raptor.py <command>`
/agentic - Scan → dedup → prep → analysis pipeline (exploitation-validator methodology) — `libexec/raptor-agentic --repo <path>`
/exploit /patch - Generate PoCs and fixes — `python3 raptor.py agentic`
/validate - Exploitability validation pipeline — stages 0 → A → B → C → D → E → F → 1 in `skills/exploitability-validation/`
/openant - OpenAnt LLM semantic scan — `libexec/raptor-openant --repo <path> [options]`
/understand - Code understanding — `libexec/raptor-understand [options]`
/diagram - Mermaid visual maps from /understand + /validate JSON outputs — `libexec/raptor-render-diagrams <out-dir>`
/audit - Hypothesis-driven code audit with deterministic tool verification — `libexec/raptor-audit [options]`
/review - Navigate audit results across all four layers — `libexec/raptor-review $ARGUMENTS`
/annotate - Per-function prose annotations — `libexec/raptor-annotate <subcommand> [args]`
/tune - Resource tuning — `libexec/raptor-tune [profile]`
/sage - SAGE persistent memory — `libexec/raptor-sage [options]`
/crash-analysis - Autonomous crash root-cause analysis for C/C++ — `libexec/raptor-study-run $ARGUMENTS`
/oss-forensics - Evidence-backed GitHub forensic investigation — `skills/oss-forensics`
/scorecard - Inspect per-model reliability across decision classes — `libexec/raptor-llm-scorecard`
/ask - Send a prompt to any configured LLM model — `libexec/raptor-llm-ask --model <name> "prompt"`
/describe - Describe a target (language mix, build system, cost estimate) — `libexec/raptor-describe --target <path>`
/binary - Black-box binary investigation — `libexec/raptor-binary <command> [args]`
/ghidra - Ghidra RE bridge — `libexec/raptor-ghidra <subcommand> [args]`
/sca - Software Composition Analysis — `python3 raptor.py sca $ARGUMENTS`
/cve-diff - CVE patch discovery — `libexec/raptor-cve-diff <subcommand> [args]`
/cve-env - CVE → Docker environment builder — `libexec/raptor-cve-env <subcommand> [args]`
/version - Show running RAPTOR framework version — `python3 raptor.py --version`

---

## DEFAULT TARGET DIRECTORY

When a command like `/scan`, `/agentic`, `/validate`, `/codeql`, or `/fuzz` is run without a path argument, resolve the default target in this order:
1. **Active project target:** session binding in `~/.local/share/raptor/sessions.d/`
2. **Caller directory:** `$RAPTOR_CALLER_DIR` (set by launcher before switching to repo root)
3. **Ask user** for target path

---

## RUN LIFECYCLE

When running analysis commands (`/scan`, `/validate`, `/understand`, `/codeql`, `/fuzz`, `/web`), use the run lifecycle stubs:

**Before starting work:**
```bash
libexec/raptor-run-lifecycle start <command> --target <resolved_target> [--out <dir>]
```
The last line of output is `OUTPUT_DIR=<path>` — use that path for all output files.

**After successful completion:**
```bash
libexec/raptor-run-lifecycle complete "$OUTPUT_DIR"
```

**On failure:**
```bash
libexec/raptor-run-lifecycle fail "$OUTPUT_DIR" "error description"
```
