"""Tests for active web runners (nuclei, dalfox, sqlmap) and tool_adapters."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.hunt.scope import ScopeConfig, ScopeViolationError
from packages.hunt.web_runners import run_dalfox, run_ffuf, run_nuclei, run_sqlmap


def _load_tool_adapters():
    path = Path(__file__).resolve().parents[2] / "web" / "tool_adapters.py"
    spec = importlib.util.spec_from_file_location("tool_adapters", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules["tool_adapters"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestExternalWebRunners:
    def test_adapters_promoted_to_external_structured(self) -> None:
        mod = _load_tool_adapters()
        dalfox = mod.web_tool_adapter("dalfox")
        sqlmap = mod.web_tool_adapter("sqlmap")
        assert dalfox.execution == "external"
        assert dalfox.parser_status == "structured"
        assert sqlmap.execution == "external"
        assert sqlmap.parser_status == "structured"

    def test_requires_approval_and_scope(self, tmp_path: Path) -> None:
        scope = ScopeConfig(in_scope=["example.com"])
        with pytest.raises(PermissionError):
            run_dalfox("https://example.com/search?q=1", scope, tmp_path, approved=False, resolve_dns=False)
        with pytest.raises(PermissionError):
            run_sqlmap("https://example.com/item?id=1", scope, tmp_path, approved=False, resolve_dns=False)
        with pytest.raises(ScopeViolationError):
            run_dalfox("https://evil.com/search?q=1", scope, tmp_path, approved=True, resolve_dns=False)

    def test_dalfox_parses_json_findings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dalfox")

        def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            stdout = '[{"type":"V","inject_type":"inHTML","poc":"https://example.com/s?q=%3Csvg/onload=alert(1)%3E","param":"q","severity":"High"}]\n'
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        scope = ScopeConfig(in_scope=["example.com"])
        res = run_dalfox("https://example.com/s?q=1", scope, tmp_path, approved=True, resolve_dns=False)
        assert res.status == "ok"
        assert len(res.findings) == 1
        assert res.findings[0]["vuln_type"] == "xss"
        assert "svg/onload=alert(1)" in res.findings[0]["poc_command"]

    def test_sqlmap_runs_batch_and_parses_injection(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/sqlmap")
        captured_cmd: list[str] = []

        def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            captured_cmd.extend(cmd)
            stdout = (
                "Parameter: id (GET)\n"
                "    Type: boolean-based blind\n"
                "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
                "    Payload: id=1 AND 1234=1234\n"
                "back-end DBMS: PostgreSQL\n"
            )
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        scope = ScopeConfig(in_scope=["example.com"])
        res = run_sqlmap("https://example.com/item?id=1", scope, tmp_path, approved=True, resolve_dns=False)
        assert "--batch" in captured_cmd
        assert res.status == "ok"
        assert len(res.findings) == 1
        assert res.findings[0]["vuln_type"] == "sqli"
        assert "PostgreSQL" in res.findings[0]["evidence"]

    def test_nuclei_parses_jsonl_findings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/nuclei")

        def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            stdout = '{"template-id":"exposed-env","info":{"name":"Exposed .env","severity":"high"},"matched-at":"https://example.com/.env"}\n'
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        scope = ScopeConfig(in_scope=["example.com"])
        res = run_nuclei("https://example.com", scope, tmp_path, approved=True, resolve_dns=False)
        assert res.status == "ok"
        assert len(res.findings) == 1
        assert res.findings[0]["severity"] == "high"
        assert res.findings[0]["target"] == "https://example.com/.env"

    def test_ffuf_requires_approval_and_reports_tool_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        scope = ScopeConfig(in_scope=["example.com"])
        wl = tmp_path / "words.txt"
        wl.write_text("admin\n", encoding="utf-8")
        with pytest.raises(PermissionError):
            run_ffuf("https://example.com", wl, scope, tmp_path, approved=False, resolve_dns=False)
        res = run_ffuf("https://example.com", wl, scope, tmp_path, approved=True, resolve_dns=False)
        assert res.status == "tool_missing"
