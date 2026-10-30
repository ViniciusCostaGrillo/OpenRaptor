from pathlib import Path

def test_setup_kali_script_syntax():
    root = Path(__file__).resolve().parent.parent
    script = root / "setup-kali.sh"
    assert script.is_file(), "setup-kali.sh deve existir"
    content = script.read_text(encoding="utf-8")
    assert "#!/usr/bin/env bash" in content
    assert "apt-get install" in content
    assert "uv" in content
    assert "semgrep" in content
    assert "opencode" in content
