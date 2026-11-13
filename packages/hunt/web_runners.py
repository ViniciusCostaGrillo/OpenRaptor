"""Active web vulnerability runners (nuclei, dalfox, sqlmap, ffuf) with Scope Guard and approval gates."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .evidence_store import EvidenceStore
from .scope import ScopeConfig, assert_in_scope


@dataclass
class WebRunResult:
    """Normalized result of an active web runner."""

    tool: str
    status: str  # ok | tool_missing | error
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""


def _require_approval(approved: bool, tool: str) -> None:
    if not approved:
        raise PermissionError(f"{tool} execution requires explicit operator approval (approved=True)")


def _header_flags(scope: ScopeConfig, flag: str = "-H") -> list[str]:
    args: list[str] = []
    for k, v in scope.headers.items():
        args.extend([flag, f"{k}: {v}"])
    if scope.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in scope.cookies.items())
        args.extend([flag, f"Cookie: {cookie_str}"])
    return args


def run_nuclei(
    target_url: str,
    scope: ScopeConfig,
    out_dir: Path,
    *,
    approved: bool = False,
    resolve_dns: bool = True,
    timeout: int = 600,
) -> WebRunResult:
    """Run nuclei against an in-scope target and record findings."""
    _require_approval(approved, "nuclei")
    assert_in_scope(target_url, scope, resolve_dns=resolve_dns)

    binary = shutil.which("nuclei")
    if not binary:
        return WebRunResult(tool="nuclei", status="tool_missing", error="nuclei not found on PATH")

    cmd = [
        binary,
        "-u",
        target_url,
        "-jsonl",
        "-silent",
        "-rl",
        str(max(1, int(scope.rate_limit_rps))),
        *_header_flags(scope, "-H"),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    store = EvidenceStore(out_dir)
    store.record_raw_output("web-nuclei", proc.stdout or proc.stderr, ext="jsonl")

    recorded: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        raw = line.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
        matched = str(obj.get("matched-at") or target_url)
        severity = str(info.get("severity") or "medium").lower()
        template_id = str(obj.get("template-id") or "other")
        name = str(info.get("name") or template_id or "Nuclei Finding")
        finding = store.record_finding(
            title=name,
            vuln_type=template_id,
            target=matched,
            severity=severity,
            tool="nuclei",
            description=str(info.get("description") or ""),
            evidence=raw,
            poc_command=f"nuclei -u {shlex.quote(matched)} -id {shlex.quote(template_id)}",
        )
        recorded.append(finding)
    return WebRunResult(
        tool="nuclei",
        status="ok" if proc.returncode == 0 else "error",
        findings=recorded,
        error=proc.stderr if proc.returncode != 0 else "",
    )


def run_dalfox(
    target_url: str,
    scope: ScopeConfig,
    out_dir: Path,
    *,
    approved: bool = False,
    resolve_dns: bool = True,
    timeout: int = 600,
) -> WebRunResult:
    """Run dalfox XSS scanner against an in-scope URL and record PoCs."""
    _require_approval(approved, "dalfox")
    assert_in_scope(target_url, scope, resolve_dns=resolve_dns)

    binary = shutil.which("dalfox")
    if not binary:
        return WebRunResult(tool="dalfox", status="tool_missing", error="dalfox not found on PATH")

    cmd = [binary, "url", target_url, "--format", "json", "--silence", *_header_flags(scope, "-H")]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    store = EvidenceStore(out_dir)
    store.record_raw_output("web-dalfox", proc.stdout or proc.stderr, ext="json")

    items: list[dict[str, Any]] = []
    try:
        parsed = json.loads(proc.stdout)
        if isinstance(parsed, list):
            items = [x for x in parsed if isinstance(x, dict)]
        elif isinstance(parsed, dict):
            items = [parsed]
    except json.JSONDecodeError:
        for line in proc.stdout.splitlines():
            try:
                obj = json.loads(line.strip())
                if isinstance(obj, dict):
                    items.append(obj)
            except json.JSONDecodeError:
                continue

    recorded: list[dict[str, Any]] = []
    for item in items:
        poc_url = str(item.get("poc") or target_url)
        param = str(item.get("param") or "")
        severity = str(item.get("severity") or "high").lower()
        finding = store.record_finding(
            title=f"XSS ({item.get('inject_type', 'reflected')}) on parameter '{param or 'url'}'",
            vuln_type="xss",
            target=target_url,
            severity=severity,
            tool="dalfox",
            cwe_id="CWE-79",
            evidence=json.dumps(item),
            poc_command=f"curl -sk {shlex.quote(poc_url)}",
            remediation="Apply context-aware output encoding and strict Content-Security-Policy.",
        )
        recorded.append(finding)
    return WebRunResult(
        tool="dalfox",
        status="ok" if proc.returncode == 0 else "error",
        findings=recorded,
        error=proc.stderr if proc.returncode != 0 else "",
    )


def run_sqlmap(
    target_url: str,
    scope: ScopeConfig,
    out_dir: Path,
    *,
    approved: bool = False,
    data: str | None = None,
    resolve_dns: bool = True,
    timeout: int = 900,
) -> WebRunResult:
    """Run sqlmap non-interactively (--batch) against an in-scope URL."""
    _require_approval(approved, "sqlmap")
    assert_in_scope(target_url, scope, resolve_dns=resolve_dns)

    binary = shutil.which("sqlmap")
    if not binary:
        return WebRunResult(tool="sqlmap", status="tool_missing", error="sqlmap not found on PATH")

    cmd = [
        binary,
        "-u",
        target_url,
        "--batch",
        "--level=1",
        "--risk=1",
        "--disable-coloring",
    ]
    if data:
        cmd.extend(["--data", data])
    if scope.headers:
        cmd.extend(["--headers", "\n".join(f"{k}: {v}" for k, v in scope.headers.items())])
    if scope.cookies:
        cmd.extend(["--cookie", "; ".join(f"{k}={v}" for k, v in scope.cookies.items())])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    store = EvidenceStore(out_dir)
    store.record_raw_output("web-sqlmap", proc.stdout or proc.stderr, ext="txt")

    param_match = re.search(r"Parameter:\s*(.+)", proc.stdout)
    type_match = re.search(r"Type:\s*(.+)", proc.stdout)
    payload_match = re.search(r"Payload:\s*(.+)", proc.stdout)
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", proc.stdout, re.IGNORECASE)

    recorded: list[dict[str, Any]] = []
    if param_match and type_match:
        param = param_match.group(1).strip()
        inj_type = type_match.group(1).strip()
        payload = payload_match.group(1).strip() if payload_match else ""
        dbms = dbms_match.group(1).strip() if dbms_match else "unknown"
        evidence = f"Parameter: {param} | Type: {inj_type} | DBMS: {dbms} | Payload: {payload}"

        finding = store.record_finding(
            title=f"SQL Injection ({inj_type}) in {param}",
            vuln_type="sqli",
            target=target_url,
            severity="critical",
            tool="sqlmap",
            cwe_id="CWE-89",
            evidence=evidence,
            poc_command=f"sqlmap -u {shlex.quote(target_url)} --batch --technique=B",
            remediation="Use parameterized queries / prepared statements for all database inputs.",
        )
        recorded.append(finding)

    return WebRunResult(
        tool="sqlmap",
        status="ok" if proc.returncode == 0 else "error",
        findings=recorded,
        error=proc.stderr if proc.returncode != 0 else "",
    )


def run_ffuf(
    target_url: str,
    wordlist: Path,
    scope: ScopeConfig,
    out_dir: Path,
    *,
    approved: bool = False,
    resolve_dns: bool = True,
    timeout: int = 600,
) -> WebRunResult:
    """Run ffuf content discovery with Scope Guard and Bug Bounty headers."""
    _require_approval(approved, "ffuf")
    fuzz_url = target_url if "FUZZ" in target_url else f"{target_url.rstrip('/')}/FUZZ"
    assert_in_scope(fuzz_url.replace("FUZZ", "test"), scope, resolve_dns=resolve_dns)

    binary = shutil.which("ffuf")
    if not binary:
        return WebRunResult(tool="ffuf", status="tool_missing", error="ffuf not found on PATH")

    out_json = Path(out_dir) / "evidence" / "raw_outputs" / "web-ffuf.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        binary,
        "-u",
        fuzz_url,
        "-w",
        str(wordlist),
        "-rate",
        str(max(1, int(scope.rate_limit_rps))),
        "-of",
        "json",
        "-o",
        str(out_json),
        "-s",
        *_header_flags(scope, "-H"),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    store = EvidenceStore(out_dir)

    recorded: list[dict[str, Any]] = []
    if out_json.is_file():
        try:
            data = json.loads(out_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
        for entry in data.get("results", []) if isinstance(data, dict) else []:
            if not isinstance(entry, dict):
                continue
            found_url = str(entry.get("url") or "")
            status_code = entry.get("status", 0)
            if not found_url:
                continue
            finding = store.record_finding(
                title=f"Discovered endpoint ({status_code}): {found_url}",
                vuln_type="content_discovery",
                target=found_url,
                severity="info",
                tool="ffuf",
                evidence=json.dumps(entry),
                poc_command=f"curl -sk {shlex.quote(found_url)}",
            )
            recorded.append(finding)

    return WebRunResult(
        tool="ffuf",
        status="ok" if proc.returncode == 0 else "error",
        findings=recorded,
        error=proc.stderr if proc.returncode != 0 else "",
    )
