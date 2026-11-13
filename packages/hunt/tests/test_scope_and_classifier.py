"""Tests for Scope Guard and Target Classifier."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from packages.hunt.classifier import TargetKind, classify_target
from packages.hunt.scope import ScopeConfig, ScopeViolationError, assert_in_scope


class TestScopeGuard:
    def test_wildcard_subdomain_matches_and_rejects_lookalike(self) -> None:
        cfg = ScopeConfig(in_scope=["*.example.com"])
        assert assert_in_scope("https://api.example.com/v1", cfg, resolve_dns=False) == "https://api.example.com/v1"
        assert assert_in_scope("sub.api.example.com", cfg, resolve_dns=False) == "sub.api.example.com"
        with pytest.raises(ScopeViolationError):
            assert_in_scope("https://badexample.com", cfg, resolve_dns=False)
        with pytest.raises(ScopeViolationError):
            assert_in_scope("https://example.com", cfg, resolve_dns=False)

    def test_out_of_scope_overrides_in_scope_wildcard(self) -> None:
        cfg = ScopeConfig(
            in_scope=["*.example.com"],
            out_of_scope=["admin.example.com", "*.internal.example.com"],
        )
        assert assert_in_scope("app.example.com", cfg, resolve_dns=False) == "app.example.com"
        with pytest.raises(ScopeViolationError):
            assert_in_scope("https://admin.example.com/login", cfg, resolve_dns=False)
        with pytest.raises(ScopeViolationError):
            assert_in_scope("db.internal.example.com", cfg, resolve_dns=False)

    def test_cidr_scope_matching(self) -> None:
        cfg = ScopeConfig(in_scope=["93.184.216.0/24"], out_of_scope=["93.184.216.10"])
        assert assert_in_scope("93.184.216.42", cfg, resolve_dns=False) == "93.184.216.42"
        with pytest.raises(ScopeViolationError):
            assert_in_scope("93.184.216.10", cfg, resolve_dns=False)
        with pytest.raises(ScopeViolationError):
            assert_in_scope("8.8.8.8", cfg, resolve_dns=False)

    def test_blocks_private_ips_directly_and_via_dns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = ScopeConfig(in_scope=["*.example.com", "127.0.0.1", "10.0.0.5"])
        with pytest.raises(ScopeViolationError):
            assert_in_scope("127.0.0.1", cfg, resolve_dns=False)
        with pytest.raises(ScopeViolationError):
            assert_in_scope("http://10.0.0.5:8080", cfg, resolve_dns=False)

        def fake_getaddrinfo(host: str, port: object, *args: object, **kwargs: object) -> list[tuple]:
            if host == "ssrf.example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        assert assert_in_scope("https://web.example.com", cfg, resolve_dns=True) == "https://web.example.com"
        with pytest.raises(ScopeViolationError):
            assert_in_scope("https://ssrf.example.com", cfg, resolve_dns=True)

    def test_allows_private_ip_when_explicitly_enabled(self) -> None:
        cfg = ScopeConfig(in_scope=["10.10.10.5"], allow_private_ips=True)
        assert assert_in_scope("10.10.10.5", cfg, resolve_dns=False) == "10.10.10.5"

    def test_url_path_scope_and_supernet_overlap(self) -> None:
        cfg = ScopeConfig(
            in_scope=["https://example.com/api"],
            out_of_scope=["https://example.com/api/admin"],
        )
        assert assert_in_scope("https://example.com/api/v1/users", cfg, resolve_dns=False)
        with pytest.raises(ScopeViolationError):
            assert_in_scope("https://example.com/login", cfg, resolve_dns=False)
        with pytest.raises(ScopeViolationError):
            assert_in_scope("https://example.com/api/admin/panel", cfg, resolve_dns=False)

        supernet_cfg = ScopeConfig(in_scope=["169.0.0.0/8"], allow_private_ips=False)
        with pytest.raises(ScopeViolationError):
            assert_in_scope("169.0.0.0/8", supernet_cfg, resolve_dns=False)


class TestTargetClassifier:
    def test_classifies_network_targets(self) -> None:
        assert classify_target("https://example.com/api").kind == TargetKind.URL
        assert classify_target("example.com").kind == TargetKind.EXTERNAL_DOMAIN
        assert classify_target("203.0.113.0/24").kind == TargetKind.IP_CIDR
        assert classify_target("203.0.113.42").kind == TargetKind.IP_CIDR

    def test_classifies_filesystem_targets(self, tmp_path: Path) -> None:
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        assert classify_target(str(repo_dir)).kind == TargetKind.REPO

        apk_file = tmp_path / "app.apk"
        apk_file.write_bytes(b"PK\x03\x04dummy")
        assert classify_target(str(apk_file)).kind == TargetKind.APK

        ipa_file = tmp_path / "app.ipa"
        ipa_file.write_bytes(b"PK\x03\x04dummy")
        assert classify_target(str(ipa_file)).kind == TargetKind.IPA

        elf_file = tmp_path / "vuln"
        elf_file.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        assert classify_target(str(elf_file)).kind == TargetKind.BINARY
