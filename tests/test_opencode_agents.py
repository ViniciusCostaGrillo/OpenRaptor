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
