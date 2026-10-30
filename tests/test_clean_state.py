from pathlib import Path

def test_no_legacy_claude_artifacts():
    root = Path(__file__).resolve().parent.parent
    assert not (root / ".claude").exists(), ".claude/ deve ser completamente removido"
    assert not (root / "CLAUDE.md").exists(), "CLAUDE.md deve ser substituído por AGENTS.md"
    assert (root / "AGENTS.md").is_file(), "AGENTS.md deve existir"
    assert (root / "opencode.json").is_file(), "opencode.json deve existir"
    assert (root / "setup-kali.sh").is_file(), "setup-kali.sh deve existir"
