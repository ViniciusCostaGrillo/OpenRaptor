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
