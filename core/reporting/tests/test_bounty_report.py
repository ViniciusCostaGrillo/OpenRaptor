"""Tests for Bug Bounty and Pentest Markdown/HTML report generator."""

from __future__ import annotations

from pathlib import Path

from core.reporting.bounty_report import generate_bounty_reports
from packages.hunt.evidence_store import EvidenceStore


class TestBountyReportGenerator:
    def test_generates_bounty_and_pentest_reports_with_html_escaping(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path)
        store.record_finding(
            title="Reflected XSS <script>alert(1)</script>",
            vuln_type="xss",
            target="https://example.com/search?q=1",
            severity="high",
            tool="dalfox",
            cwe_id="CWE-79",
            cvss_score=7.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            description="Unsanitized reflection in query parameter q.",
            evidence="<script>alert(1)</script>",
            poc_command="curl -sk 'https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E'",
            remediation="Encode output contextually.",
        )

        outputs = generate_bounty_reports(tmp_path, target="https://example.com", platform="hackerone")
        assert outputs["bounty_md"].is_file()
        assert outputs["pentest_md"].is_file()
        assert outputs["pentest_html"].is_file()

        bounty_text = outputs["bounty_md"].read_text(encoding="utf-8")
        assert "CWE-79" in bounty_text
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" in bounty_text
        assert "Steps to Reproduce" in bounty_text

        html_text = outputs["pentest_html"].read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in html_text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text

    def test_handles_empty_findings_cleanly(self, tmp_path: Path) -> None:
        outputs = generate_bounty_reports(tmp_path, target="example.com")
        text = outputs["bounty_md"].read_text(encoding="utf-8")
        assert "No confirmed vulnerabilities" in text
