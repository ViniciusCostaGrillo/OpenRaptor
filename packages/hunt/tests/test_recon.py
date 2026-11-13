"""Tests for Kali recon runners and structured parsers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.hunt.recon import (
    parse_nmap_xml,
    run_httpx,
    run_katana,
    run_nmap,
    run_subfinder,
)
from packages.hunt.scope import ScopeConfig, ScopeViolationError


class TestReconRunners:
    def test_missing_binary_returns_tool_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        scope = ScopeConfig(in_scope=["example.com", "*.example.com"])
        res = run_subfinder("example.com", scope, tmp_path, approved=False) if False else None
        with pytest.raises(PermissionError):
            run_subfinder("example.com", scope, tmp_path, approved=False)
        res = run_subfinder("example.com", scope, tmp_path, approved=True)
        assert res.status == "tool_missing"
        assert res.items == []

    def test_subfinder_filters_out_of_scope_subdomains(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/subfinder")

        def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            stdout = (
                '{"host":"api.example.com"}\n'
                '{"host":"admin.example.com"}\n'
                '{"host":"evil.com"}\n'
            )
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        scope = ScopeConfig(
            in_scope=["*.example.com"],
            out_of_scope=["admin.example.com"],
        )
        res = run_subfinder("example.com", scope, tmp_path, approved=False) if False else None
        with pytest.raises(PermissionError):
            run_subfinder("example.com", scope, tmp_path, approved=False)
        res = run_subfinder("example.com", scope, tmp_path, approved=True)
        assert res.status == "ok"
        assert [item["host"] for item in res.items] == ["api.example.com"]

    def test_httpx_parses_jsonl_and_propagates_headers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/httpx")
        captured_cmd: list[str] = []

        def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            captured_cmd.extend(cmd)
            stdout = (
                '{"url":"https://api.example.com","status_code":200,"title":"API","tech":["Nginx"]}\n'
                'not-json\n'
            )
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        scope = ScopeConfig(
            in_scope=["*.example.com"],
            headers={"X-Bug-Bounty": "hackerone"},
        )
        res = run_httpx(["https://api.example.com"], scope, tmp_path, approved=True, resolve_dns=False)
        assert res.status == "ok"
        assert len(res.items) == 1
        assert res.items[0]["status_code"] == 200
        assert "X-Bug-Bounty: hackerone" in captured_cmd

    def test_nmap_xml_parser_and_truncated_xml(self) -> None:
        xml_ok = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="93.184.216.34" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https" product="nginx" version="1.24"/>
              </port>
              <port protocol="tcp" portid="80">
                <state state="closed"/>
                <service name="http"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        parsed = parse_nmap_xml(xml_ok)
        assert len(parsed) == 1
        assert parsed[0]["port"] == 443
        assert parsed[0]["service"] == "https"

        assert parse_nmap_xml("<nmaprun><host><broken") == []

    def test_katana_filters_endpoints_and_blocks_out_of_scope_url(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scope = ScopeConfig(in_scope=["api.example.com"])
        with pytest.raises(ScopeViolationError):
            run_nmap("evil.com", scope, tmp_path, approved=True, resolve_dns=False)

        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/katana")

        def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
            stdout = (
                '{"request":{"endpoint":"https://api.example.com/v1/users"}}\n'
                '{"request":{"endpoint":"https://thirdparty.com/cdn.js"}}\n'
            )
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        res = run_katana("https://api.example.com", scope, tmp_path, approved=True, resolve_dns=False)
        assert res.status == "ok"
        assert [item["url"] for item in res.items] == ["https://api.example.com/v1/users"]
