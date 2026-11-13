"""Tests for resumable Action Planner and EvidenceStore."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.hunt.evidence_store import EvidenceStore
from packages.hunt.planner import (
    ActionStatus,
    approve_action,
    init_hunt_session,
    mark_action_result,
    propose_next_action,
    reject_action,
    require_approved_action,
)
from packages.hunt.scope import ScopeConfig


class TestResumablePlanner:
    def test_init_and_propose_persists_across_reloads(self, tmp_path: Path) -> None:
        scope = ScopeConfig(in_scope=["example.com", "*.example.com"])
        state = init_hunt_session(tmp_path, "example.com", scope)
        assert state.target == "example.com"
        assert (tmp_path / "hunt_state.json").is_file()

        first = propose_next_action(tmp_path)
        assert first is not None
        assert first.status == ActionStatus.PENDING
        assert first.tool == "subfinder"

        # Calling propose_next_action again before resolving returns the same pending proposal
        again = propose_next_action(tmp_path)
        assert again is not None
        assert again.id == first.id

    def test_require_approved_action_enforces_approval_gate(self, tmp_path: Path) -> None:
        scope = ScopeConfig(in_scope=["https://example.com"])
        init_hunt_session(tmp_path, "https://example.com", scope)
        proposal = propose_next_action(tmp_path)
        assert proposal is not None

        with pytest.raises(PermissionError):
            require_approved_action(tmp_path, proposal.id)

        approved = approve_action(tmp_path, proposal.id)
        assert approved.status == ActionStatus.APPROVED
        assert require_approved_action(tmp_path, proposal.id).id == proposal.id

        mark_action_result(tmp_path, proposal.id, executed=True, summary="ok")
        nxt = propose_next_action(tmp_path)
        assert nxt is not None
        assert nxt.id != proposal.id

        rejected = reject_action(tmp_path, nxt.id, reason="skip noisy scan")
        assert rejected.status == ActionStatus.REJECTED
        with pytest.raises(PermissionError):
            require_approved_action(tmp_path, nxt.id)


class TestEvidenceStore:
    def test_records_findings_raw_outputs_and_http_traces(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path)
        f1 = store.record_finding(
            title="Reflected XSS in /search",
            vuln_type="xss",
            target="https://example.com/search?q=1",
            severity="high",
            cwe_id="CWE-79",
            cvss_score=7.1,
            poc_command="curl -s 'https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E'",
            remediation="Encode output contextually.",
        )
        # Duplicate finding should deduplicate instead of duplicating entries
        store.record_finding(
            title="Reflected XSS in /search",
            vuln_type="xss",
            target="https://example.com/search?q=1",
            severity="high",
        )
        findings = store.load_findings()
        assert len(findings) == 1
        assert findings[0]["id"] == f1["id"]

        raw_path = store.record_raw_output("act-001", "nmap output line")
        trace_path = store.record_http_trace("act-001", "GET / HTTP/1.1", "HTTP/1.1 200 OK")
        assert raw_path.is_file()
        assert trace_path.is_file()
