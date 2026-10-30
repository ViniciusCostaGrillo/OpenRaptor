from unittest.mock import patch, MagicMock
from core.llm.opencode_adapter import parse_opencode_json_stream, run_opencode_turn

def test_parse_opencode_json_stream():
    sample_stream = (
        '{"type":"step_start"}\n'
        '{"type":"text","content":"Vulnerabilidade detectada: SQL Injection"}\n'
        '{"type":"step_finish"}\n'
    )
    result = parse_opencode_json_stream(sample_stream)
    assert "SQL Injection" in result

@patch("subprocess.Popen")
def test_run_opencode_turn(mock_popen):
    mock_proc = MagicMock()
    mock_proc.communicate.return_value = (
        '{"type":"text","content":"Resposta segura"}'.encode("utf-8"),
        b""
    )
    mock_proc.returncode = 0
    mock_popen.return_value = mock_proc
    output = run_opencode_turn("Analise o código", model="mock-model")
    assert "Resposta segura" in output
