"""Bug Bounty (HackerOne/Bugcrowd) and Pentest report generator."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from packages.exploitation.poc_generator import generate_http_poc
from packages.hunt.evidence_store import EvidenceStore

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>OpenRaptor Security Assessment Report - {{ target }}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; margin: 2rem auto; max-width: 980px; color: #1f2937; line-height: 1.5; }
    h1, h2, h3 { color: #111827; }
    .summary { display: flex; gap: 1rem; margin: 1rem 0; }
    .card { border: 1px solid #d1d5db; border-radius: 8px; padding: 0.75rem 1rem; min-width: 100px; }
    .finding { border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
    .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 600; text-transform: uppercase; font-size: 0.8rem; background: #fee2e2; color: #991b1b; }
    pre { background: #111827; color: #f9fafb; padding: 0.75rem; border-radius: 6px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>OpenRaptor Security Assessment Report</h1>
  <p><strong>Target:</strong> {{ target }} | <strong>Generated:</strong> {{ generated_at }}</p>
  <h2>Executive Summary</h2>
  <div class="summary">
    <div class="card"><strong>Total:</strong> {{ findings|length }}</div>
    <div class="card"><strong>Critical:</strong> {{ counts.get("critical", 0) }}</div>
    <div class="card"><strong>High:</strong> {{ counts.get("high", 0) }}</div>
    <div class="card"><strong>Medium:</strong> {{ counts.get("medium", 0) }}</div>
    <div class="card"><strong>Low:</strong> {{ counts.get("low", 0) }}</div>
  </div>
  {% if not findings %}
  <p>No confirmed vulnerabilities were recorded.</p>
  {% else %}
  {% for f in findings %}
  <div class="finding">
    <h3>{{ f.id }} - {{ f.title }}</h3>
    <p><span class="badge">{{ f.severity }}</span>
       <strong>Target:</strong> {{ f.target }}
       {% if f.cwe_id %}| <strong>CWE:</strong> {{ f.cwe_id }}{% endif %}
       {% if f.cvss_score %}| <strong>CVSS:</strong> {{ f.cvss_score }}{% endif %}
    </p>
    {% if f.description %}<p>{{ f.description }}</p>{% endif %}
    {% if f.poc_command %}<h4>PoC</h4><pre>{{ f.poc_command }}</pre>{% endif %}
    {% if f.evidence %}<h4>Evidence</h4><pre>{{ f.evidence }}</pre>{% endif %}
    {% if f.remediation %}<h4>Remediation</h4><p>{{ f.remediation }}</p>{% endif %}
  </div>
  {% endfor %}
  {% endif %}
</body>
</html>
"""


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity", "medium")).lower(), 99),
    )


def _render_bounty_markdown(findings: list[dict[str, Any]], target: str, platform: str, generated_at: str) -> str:
    lines = [
        f"# Bug Bounty Submission Report ({platform.title()})",
        "",
        f"- **Target:** `{target}`",
        f"- **Generated:** {generated_at}",
        f"- **Total Findings:** {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No confirmed vulnerabilities were recorded.")
        return "\n".join(lines) + "\n"

    for f in findings:
        lines.extend([
            "---",
            "",
            f"## [{str(f.get('severity', 'medium')).upper()}] {f.get('title', 'Untitled Finding')}",
            "",
            f"- **ID:** {f.get('id', '—')}",
            f"- **Asset:** `{f.get('target', target)}`",
            f"- **Weakness / CWE:** {f.get('cwe_id') or f.get('vuln_type') or '—'}",
            f"- **CVSS:** {f.get('cvss_score') or '—'} ({f.get('cvss_vector') or '—'})",
            f"- **Tool:** `{f.get('tool', 'manual')}`",
            "",
            "### Summary",
            str(f.get("description") or "Vulnerability identified during authorized security testing."),
            "",
            "### Steps to Reproduce / PoC",
            "```bash",
            str(f.get("poc_command") or f"# Target: {f.get('target', target)}"),
            "```",
            "",
            "### Supporting Evidence",
            "```text",
            str(f.get("evidence") or "See raw outputs in evidence directory."),
            "```",
            "",
            "### Impact & Remediation",
            str(f.get("remediation") or "Apply defense-in-depth validation and least-privilege controls."),
            "",
        ])
    return "\n".join(lines)


def _render_pentest_markdown(findings: list[dict[str, Any]], target: str, counts: Counter[str], generated_at: str) -> str:
    lines = [
        "# Penetration Test & Security Assessment Report",
        "",
        f"- **Target:** `{target}`",
        f"- **Generated:** {generated_at}",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| Critical | {counts.get('critical', 0)} |",
        f"| High | {counts.get('high', 0)} |",
        f"| Medium | {counts.get('medium', 0)} |",
        f"| Low | {counts.get('low', 0)} |",
        f"| Info | {counts.get('info', 0) + counts.get('informational', 0)} |",
        "",
    ]
    if not findings:
        lines.append("No confirmed vulnerabilities were recorded.")
        return "\n".join(lines) + "\n"

    lines.append("## Technical Findings\n")
    for f in findings:
        lines.extend([
            f"### {f.get('id', '')} — {f.get('title', '')} ({str(f.get('severity', '')).upper()})",
            f"- **Target:** `{f.get('target', '')}`",
            f"- **CWE:** {f.get('cwe_id') or '—'} | **CVSS:** {f.get('cvss_score') or '—'}",
            f"- **PoC:** `{f.get('poc_command') or 'N/A'}`",
            f"- **Remediation:** {f.get('remediation') or 'N/A'}",
            "",
        ])
    return "\n".join(lines)


def _enrich_findings_with_traces(findings: list[dict[str, Any]], out_dir: Path) -> list[dict[str, Any]]:
    """Attach http_trace raw request/response and fallback PoC when available."""
    traces_dir = out_dir / "evidence" / "http_traces"
    enriched: list[dict[str, Any]] = []
    for f in findings:
        item = dict(f)
        trace_id = item.get("http_trace_id")
        if trace_id and traces_dir.is_dir():
            trace_file = traces_dir / f"{trace_id}.json"
            if trace_file.is_file():
                try:
                    trace_data = json.loads(trace_file.read_text(encoding="utf-8"))
                    req_raw = str(trace_data.get("request", ""))
                    resp_raw = str(trace_data.get("response", ""))
                    item["evidence"] = (
                        f"{item.get('evidence', '')}\n\n[HTTP Request]\n{req_raw}\n\n[HTTP Response]\n{resp_raw}".strip()
                    )
                except (OSError, json.JSONDecodeError):
                    pass
        if not item.get("poc_command") and str(item.get("target", "")).startswith(("http://", "https://")):
            item["poc_command"] = generate_http_poc(item)
        enriched.append(item)
    return enriched


def generate_bounty_reports(
    out_dir: Path,
    *,
    target: str,
    platform: str = "generic",
) -> dict[str, Path]:
    """Generate Bug Bounty Markdown, Pentest Markdown, and Pentest HTML reports."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    findings = _enrich_findings_with_traces(_sort_findings(EvidenceStore(out).load_findings()), out)
    counts = Counter(str(f.get("severity", "medium")).lower() for f in findings)
    generated_at = datetime.now(UTC).isoformat()

    bounty_md_path = out / "bounty-report.md"
    pentest_md_path = out / "pentest-report.md"
    pentest_html_path = out / "pentest-report.html"

    bounty_md_path.write_text(
        _render_bounty_markdown(findings, target, platform, generated_at),
        encoding="utf-8",
    )
    pentest_md_path.write_text(
        _render_pentest_markdown(findings, target, counts, generated_at),
        encoding="utf-8",
    )

    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(_HTML_TEMPLATE)
    pentest_html_path.write_text(
        template.render(
            target=target,
            generated_at=generated_at,
            findings=findings,
            counts=dict(counts),
        ),
        encoding="utf-8",
    )

    return {
        "bounty_md": bounty_md_path,
        "pentest_md": pentest_md_path,
        "pentest_html": pentest_html_path,
    }
