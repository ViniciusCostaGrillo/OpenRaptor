from pathlib import Path

EXPECTED_COMMANDS = [
    "agentic", "analyze", "annotate", "ask", "audit", "binary", "codeql",
    "commands", "crash-analysis", "create-skill", "cve-diff", "cve-env",
    "describe", "diagram", "exploit", "frida", "fuzz", "ghidra",
    "openant", "oss-forensics", "patch", "project", "raptor-frida",
    "raptor-fuzz", "raptor-sca", "raptor-scan", "raptor-web", "raptor",
    "review", "sage", "sca", "scan", "scorecard", "threat-model",
    "tune", "understand", "validate", "version", "web"
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
