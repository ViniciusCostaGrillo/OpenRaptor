"""Kali Linux recon runners and structured parsers (subfinder, httpx, nmap, katana)."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as DET

from .evidence_store import EvidenceStore
from .scope import ScopeConfig, ScopeViolationError, assert_in_scope, extract_host, matches_rule


def _require_approval(approved: bool, tool: str) -> None:
    if not approved:
        raise PermissionError(f"{tool} execution requires explicit operator approval (approved=True)")


@dataclass
class ReconResult:
    """Normalized output of a recon tool execution."""

    tool: str
    status: str  # ok | tool_missing | error
    items: list[dict[str, Any]] = field(default_factory=list)
    raw_output_path: Path | None = None
    error: str = ""


def _build_header_args(scope: ScopeConfig, flag: str = "-H") -> list[str]:
    args: list[str] = []
    for k, v in scope.headers.items():
        args.extend([flag, f"{k}: {v}"])
    if scope.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in scope.cookies.items())
        args.extend([flag, f"Cookie: {cookie_str}"])
    return args


def _parse_jsonl(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    """Parse nmap -oX XML output into a list of open port records."""
    if not xml_text.strip():
        return []
    try:
        root = DET.fromstring(xml_text)
    except Exception:
        return []

    results: list[dict[str, Any]] = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.attrib.get("addr", "") if addr_el is not None else ""
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            results.append(
                {
                    "host": addr,
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "port": int(port_el.attrib.get("portid", "0")),
                    "service": svc_el.attrib.get("name", "") if svc_el is not None else "",
                    "product": svc_el.attrib.get("product", "") if svc_el is not None else "",
                    "version": svc_el.attrib.get("version", "") if svc_el is not None else "",
                }
            )
    return results


def run_subfinder(
    domain: str,
    scope: ScopeConfig,
    out_dir: Path,
    *,
    approved: bool = False,
    resolve_dns: bool = False,
    timeout: int = 300,
) -> ReconResult:
    """Run subfinder passively and keep only in-scope subdomains."""
    _require_approval(approved, "subfinder")
    try:
        assert_in_scope(domain, scope, resolve_dns=resolve_dns)
    except ScopeViolationError:
        # Allow passive subdomain enumeration of example.com when *.example.com is in scope
        # and domain itself is not excluded by any out_of_scope rule.
        for excluded in scope.out_of_scope:
            if matches_rule(domain, excluded):
                raise
        wildcard_allowed = any(
            extract_host(rule).lower() == f"*.{domain.lower()}" for rule in scope.in_scope
        )
        if not wildcard_allowed:
            raise
    binary = shutil.which("subfinder")
    if not binary:
        return ReconResult(tool="subfinder", status="tool_missing", error="subfinder not found on PATH")

    cmd = [binary, "-d", domain, "-silent", "-oJ"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    raw_path = EvidenceStore(out_dir).record_raw_output("recon-subfinder", proc.stdout or proc.stderr, ext="jsonl")

    in_scope_items: list[dict[str, Any]] = []
    for row in _parse_jsonl(proc.stdout):
        host = str(row.get("host") or "").strip()
        if not host:
            continue
        try:
            assert_in_scope(host, scope, resolve_dns=False)
            in_scope_items.append({"host": host, "source": row.get("source", "subfinder")})
        except ScopeViolationError:
            continue

    return ReconResult(
        tool="subfinder",
        status="ok" if proc.returncode == 0 else "error",
        items=in_scope_items,
        raw_output_path=raw_path,
        error=proc.stderr if proc.returncode != 0 else "",
    )


def run_httpx(
    targets: list[str],
    scope: ScopeConfig,
    out_dir: Path,
    *,
    approved: bool = False,
    resolve_dns: bool = True,
    timeout: int = 300,
) -> ReconResult:
    """Probe in-scope HTTP/HTTPS targets using httpx."""
    _require_approval(approved, "httpx")
    verified = [assert_in_scope(t, scope, resolve_dns=resolve_dns) for t in targets]
    binary = shutil.which("httpx")
    if not binary:
        return ReconResult(tool="httpx", status="tool_missing", error="httpx not found on PATH")

    cmd = [
        binary,
        "-silent",
        "-json",
        "-tech-detect",
        "-rl",
        str(max(1, int(scope.rate_limit_rps))),
        *_build_header_args(scope, "-H"),
    ]
    proc = subprocess.run(
        cmd,
        input="\n".join(verified) + "\n",
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    raw_path = EvidenceStore(out_dir).record_raw_output("recon-httpx", proc.stdout or proc.stderr, ext="jsonl")
    items = _parse_jsonl(proc.stdout)
    return ReconResult(
        tool="httpx",
        status="ok" if proc.returncode == 0 else "error",
        items=items,
        raw_output_path=raw_path,
        error=proc.stderr if proc.returncode != 0 else "",
    )


def run_nmap(
    target: str,
    scope: ScopeConfig,
    out_dir: Path,
    *,
    approved: bool = False,
    ports: str = "--top-ports 1000",
    resolve_dns: bool = True,
    timeout: int = 600,
) -> ReconResult:
    """Run nmap service discovery with XML output parsed via defusedxml."""
    _require_approval(approved, "nmap")
    assert_in_scope(target, scope, resolve_dns=resolve_dns)
    binary = shutil.which("nmap")
    if not binary:
        return ReconResult(tool="nmap", status="tool_missing", error="nmap not found on PATH")

    cmd = [binary, "-sV", *shlex.split(ports), "-oX", "-", target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    raw_path = EvidenceStore(out_dir).record_raw_output("recon-nmap", proc.stdout or proc.stderr, ext="xml")
    items = parse_nmap_xml(proc.stdout)
    return ReconResult(
        tool="nmap",
        status="ok" if proc.returncode == 0 else "error",
        items=items,
        raw_output_path=raw_path,
        error=proc.stderr if proc.returncode != 0 else "",
    )


def run_katana(
    url: str,
    scope: ScopeConfig,
    out_dir: Path,
    *,
    approved: bool = False,
    depth: int = 3,
    resolve_dns: bool = True,
    timeout: int = 300,
) -> ReconResult:
    """Crawl an in-scope URL with katana and keep only in-scope endpoints."""
    _require_approval(approved, "katana")
    assert_in_scope(url, scope, resolve_dns=resolve_dns)
    binary = shutil.which("katana")
    if not binary:
        return ReconResult(tool="katana", status="tool_missing", error="katana not found on PATH")

    cmd = [
        binary,
        "-u",
        url,
        "-d",
        str(depth),
        "-silent",
        "-jsonl",
        "-rl",
        str(max(1, int(scope.rate_limit_rps))),
        *_build_header_args(scope, "-H"),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    raw_path = EvidenceStore(out_dir).record_raw_output("recon-katana", proc.stdout or proc.stderr, ext="jsonl")

    items: list[dict[str, Any]] = []
    for row in _parse_jsonl(proc.stdout):
        req = row.get("request") if isinstance(row.get("request"), dict) else {}
        endpoint = str(req.get("endpoint") or row.get("endpoint") or "").strip()
        if not endpoint:
            continue
        try:
            assert_in_scope(endpoint, scope, resolve_dns=False)
            items.append({"url": endpoint, "method": req.get("method", "GET")})
        except ScopeViolationError:
            continue

    return ReconResult(
        tool="katana",
        status="ok" if proc.returncode == 0 else "error",
        items=items,
        raw_output_path=raw_path,
        error=proc.stderr if proc.returncode != 0 else "",
    )
