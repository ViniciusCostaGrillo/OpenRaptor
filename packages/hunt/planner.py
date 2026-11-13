"""Resumable disk-persisted action planner with mandatory approval gates."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from .classifier import TargetClassification, TargetKind, classify_target
from .scope import ScopeConfig


class ActionStatus(StrEnum):
    """Lifecycle status of an ActionProposal."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class ActionProposal(BaseModel):
    """One discrete step proposed to the operator before execution."""

    id: str
    phase: str
    tool: str
    target: str
    command_preview: str
    risk_level: str  # passive | local | active-recon | active | intrusive
    expected_evidence: str
    status: ActionStatus = ActionStatus.PENDING
    reason: str = ""
    summary: str = ""


class HuntSessionState(BaseModel):
    """Persisted /hunt state machine."""

    target: str
    classification: str
    recommended_pipeline: str
    scope: ScopeConfig
    actions: list[ActionProposal] = Field(default_factory=list)


def _state_path(out_dir: Path) -> Path:
    return Path(out_dir) / "hunt_state.json"


def _save_state(out_dir: Path, state: HuntSessionState) -> None:
    path = _state_path(out_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(state.model_dump_json(indent=2), encoding="utf-8")
    tmp.replace(path)


def load_hunt_session(out_dir: Path) -> HuntSessionState:
    """Load HuntSessionState from disk."""
    path = _state_path(out_dir)
    if not path.is_file():
        raise FileNotFoundError(f"No hunt_state.json found in {out_dir}")
    return HuntSessionState.model_validate_json(path.read_text(encoding="utf-8"))


def _build_initial_actions(classification: TargetClassification) -> list[ActionProposal]:
    t = classification.target
    kind = classification.kind
    specs: list[tuple[str, str, str, str, str]] = []

    if kind == TargetKind.EXTERNAL_DOMAIN:
        specs = [
            ("recon", "subfinder", f"subfinder -d {t} -silent -oJ", "passive", "Subdomínios em escopo"),
            ("recon", "httpx", f"httpx -l subdomains.txt -json -tech-detect", "active-recon", "Hosts HTTP vivos e tecnologias"),
            ("recon", "nmap", f"nmap -sV --top-ports 1000 -oX nmap.xml {t}", "active-recon", "Portas e serviços expostos"),
            ("discovery", "katana", f"katana -u https://{t} -d 3 -jsonl", "active-recon", "Endpoints e parâmetros web"),
            ("scan", "nuclei", f"nuclei -u https://{t} -jsonl", "active", "Templates de vulnerabilidades conhecidos"),
            ("exploit", "dalfox", f"dalfox url https://{t} --format json", "active", "Confirmação de XSS com PoC"),
            ("exploit", "sqlmap", f"sqlmap -u https://{t} --batch --level=1 --risk=1", "intrusive", "Confirmação de SQLi"),
            ("report", "bounty_report", f"python3 raptor.py report --out <out_dir>", "local", "Relatórios Bug Bounty e Pentest"),
        ]
    elif kind == TargetKind.URL:
        specs = [
            ("recon", "httpx", f"httpx -u {t} -json -tech-detect", "active-recon", "Headers, status e stack tecnológica"),
            ("discovery", "katana", f"katana -u {t} -d 3 -jsonl", "active-recon", "Endpoints, formulários e parâmetros"),
            ("scan", "nuclei", f"nuclei -u {t} -jsonl", "active", "Vulnerabilidades conhecidas e misconfigs"),
            ("exploit", "dalfox", f"dalfox url {t} --format json", "active", "Confirmação de XSS"),
            ("exploit", "sqlmap", f"sqlmap -u {t} --batch --level=1 --risk=1", "intrusive", "Confirmação de SQLi"),
            ("report", "bounty_report", f"python3 raptor.py report --out <out_dir>", "local", "Relatórios Bug Bounty e Pentest"),
        ]
    elif kind == TargetKind.IP_CIDR:
        specs = [
            ("recon", "nmap", f"nmap -sV --top-ports 1000 -oX nmap.xml {t}", "active-recon", "Portas e serviços"),
            ("recon", "httpx", f"httpx -u {t} -json -tech-detect", "active-recon", "Serviços web ativos"),
            ("scan", "nuclei", f"nuclei -u {t} -jsonl", "active", "CVEs e misconfigs de rede/web"),
            ("report", "bounty_report", f"python3 raptor.py report --out <out_dir>", "local", "Relatórios Bug Bounty e Pentest"),
        ]
    elif kind == TargetKind.APK:
        specs = [
            ("mobile", "apk_analyzer", f"python3 raptor.py mobile --apk {t}", "local", "Manifest, endpoints, segredos e libs .so"),
            ("re", "ghidra_rea", f"Ghidra headless / REA MCP nas libs .so extraídas", "local", "Decompilação e sinks nativos"),
            ("report", "bounty_report", f"python3 raptor.py report --out <out_dir>", "local", "Relatórios Bug Bounty e Pentest"),
        ]
    elif kind == TargetKind.BINARY:
        specs = [
            ("re", "binary_investigate", f"python3 raptor.py binary investigate {t}", "local", "Símbolos, mitigações e strings"),
            ("re", "ghidra_rea", f"python3 raptor.py ghidra import {t} (ou REA MCP)", "local", "Decompilação e análise de fluxo"),
            ("report", "bounty_report", f"python3 raptor.py report --out <out_dir>", "local", "Relatórios Bug Bounty e Pentest"),
        ]
    else:
        specs = [
            ("sast", "agentic", f"libexec/raptor-agentic --repo {t}", "local", "SAST + validação de explorabilidade + patches"),
            ("report", "bounty_report", f"python3 raptor.py report --out <out_dir>", "local", "Relatórios Bug Bounty e Pentest"),
        ]

    return [
        ActionProposal(
            id=f"act-{idx:03d}",
            phase=phase,
            tool=tool,
            target=t,
            command_preview=cmd,
            risk_level=risk,
            expected_evidence=ev,
        )
        for idx, (phase, tool, cmd, risk, ev) in enumerate(specs, start=1)
    ]


def init_hunt_session(out_dir: Path, target: str, scope: ScopeConfig) -> HuntSessionState:
    """Initialize and persist a new /hunt session state."""
    classification = classify_target(target)
    state = HuntSessionState(
        target=target,
        classification=classification.kind.value,
        recommended_pipeline=classification.recommended_pipeline,
        scope=scope,
        actions=_build_initial_actions(classification),
    )
    _save_state(out_dir, state)
    return state


def propose_next_action(out_dir: Path) -> ActionProposal | None:
    """Return the next pending or approved-not-executed ActionProposal, if any."""
    state = load_hunt_session(out_dir)
    for action in state.actions:
        if action.status in {ActionStatus.PENDING, ActionStatus.APPROVED}:
            return action
    return None


def approve_action(out_dir: Path, action_id: str) -> ActionProposal:
    """Mark an action as approved by the operator."""
    state = load_hunt_session(out_dir)
    for action in state.actions:
        if action.id == action_id:
            action.status = ActionStatus.APPROVED
            _save_state(out_dir, state)
            return action
    raise KeyError(f"Action not found: {action_id}")


def reject_action(out_dir: Path, action_id: str, reason: str = "") -> ActionProposal:
    """Mark an action as rejected by the operator."""
    state = load_hunt_session(out_dir)
    for action in state.actions:
        if action.id == action_id:
            action.status = ActionStatus.REJECTED
            action.reason = reason
            _save_state(out_dir, state)
            return action
    raise KeyError(f"Action not found: {action_id}")


def require_approved_action(out_dir: Path, action_id: str) -> ActionProposal:
    """Verify an action is explicitly approved before execution."""
    state = load_hunt_session(out_dir)
    for action in state.actions:
        if action.id == action_id:
            if action.status != ActionStatus.APPROVED:
                raise PermissionError(
                    f"Action {action_id} ({action.tool}) is {action.status.value}, not approved"
                )
            return action
    raise KeyError(f"Action not found: {action_id}")


def mark_action_result(
    out_dir: Path,
    action_id: str,
    *,
    executed: bool,
    summary: str = "",
) -> ActionProposal:
    """Record execution completion or failure for an action."""
    state = load_hunt_session(out_dir)
    for action in state.actions:
        if action.id == action_id:
            action.status = ActionStatus.EXECUTED if executed else ActionStatus.FAILED
            action.summary = summary
            _save_state(out_dir, state)
            return action
    raise KeyError(f"Action not found: {action_id}")
