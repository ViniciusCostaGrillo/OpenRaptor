from pathlib import Path

def test_launcher_invokes_opencode():
    root = Path(__file__).resolve().parent.parent
    launcher = root / "bin" / "raptor"
    content = launcher.read_text(encoding="utf-8")
    assert "opencode" in content, "bin/raptor deve invocar o binário opencode"
    assert "trap" in content, "bin/raptor deve ter trap de saída para lifecycle hook"
