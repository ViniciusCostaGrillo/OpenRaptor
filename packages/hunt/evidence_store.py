"""Structured evidence storage for /hunt, /recon, /mobile, and /report."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return cleaned or "item"


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


class EvidenceStore:
    """Persists normalized findings, raw tool outputs, and HTTP traces."""

    def __init__(self, out_dir: Path) -> None:
        self.out_dir = Path(out_dir)
        self.evidence_dir = self.out_dir / "evidence"
        self.findings_path = self.evidence_dir / "findings.json"
        self.raw_dir = self.evidence_dir / "raw_outputs"
        self.traces_dir = self.evidence_dir / "http_traces"

    def load_findings(self) -> list[dict[str, Any]]:
        """Load all recorded findings from findings.json."""
        if not self.findings_path.is_file():
            return []
        data = json.loads(self.findings_path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []

    def record_finding(
        self,
        *,
        title: str,
        vuln_type: str,
        target: str,
        severity: str = "medium",
        tool: str = "manual",
        cwe_id: str | None = None,
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        description: str = "",
        evidence: str = "",
        poc_command: str = "",
        http_trace_id: str | None = None,
        remediation: str = "",
    ) -> dict[str, Any]:
        """Record a normalized finding, deduplicating by (title, vuln_type, target)."""
        findings = self.load_findings()
        key = (title.strip().lower(), vuln_type.strip().lower(), target.strip())
        for existing in findings:
            existing_key = (
                str(existing.get("title", "")).strip().lower(),
                str(existing.get("vuln_type", "")).strip().lower(),
                str(existing.get("target", "")).strip(),
            )
            if existing_key == key:
                return existing

        finding = {
            "id": f"HUNT-{len(findings) + 1:04d}",
            "title": title,
            "vuln_type": vuln_type,
            "target": target,
            "severity": severity.lower(),
            "tool": tool,
            "cwe_id": cwe_id,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "description": description,
            "evidence": evidence,
            "poc_command": poc_command,
            "http_trace_id": http_trace_id,
            "remediation": remediation,
            "recorded_at": datetime.now(UTC).isoformat(),
        }
        findings.append(finding)
        _atomic_write_text(self.findings_path, json.dumps(findings, indent=2))
        return finding

    def record_raw_output(self, action_id: str, output: str, ext: str = "txt") -> Path:
        """Persist raw tool stdout/output for an action."""
        path = self.raw_dir / f"{_safe_id(action_id)}.{ext.lstrip('.')}"
        _atomic_write_text(path, output)
        return path

    def record_http_trace(
        self,
        trace_id: str,
        request_raw: str,
        response_raw: str,
        *,
        url: str = "",
    ) -> Path:
        """Persist an HTTP request/response pair for PoC and report evidence."""
        path = self.traces_dir / f"{_safe_id(trace_id)}.json"
        payload = {
            "trace_id": trace_id,
            "url": url,
            "request": request_raw,
            "response": response_raw,
            "recorded_at": datetime.now(UTC).isoformat(),
        }
        _atomic_write_text(path, json.dumps(payload, indent=2))
        return path
