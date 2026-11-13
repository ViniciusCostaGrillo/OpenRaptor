"""CLI entrypoint for /hunt, /recon, /mobile, and /report."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

from core.reporting.bounty_report import generate_bounty_reports
from packages.mobile.apk_analyzer import analyze_apk

from .planner import (
    approve_action,
    init_hunt_session,
    load_hunt_session,
    mark_action_result,
    propose_next_action,
    reject_action,
    require_approved_action,
)
from .recon import run_httpx, run_katana, run_nmap, run_subfinder
from .scope import ScopeConfig
from .web_runners import run_dalfox, run_nuclei, run_sqlmap


def _load_scope(scope_path: str | None, target: str) -> ScopeConfig:
    if scope_path:
        return ScopeConfig.from_file(Path(scope_path))
    return ScopeConfig.from_target(target)


def _load_subfinder_hosts(out_dir: Path) -> list[str]:
    sub_file = out_dir / "evidence" / "raw_outputs" / "recon-subfinder.jsonl"
    if not sub_file.is_file():
        return []
    hosts: list[str] = []
    for line in sub_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            obj = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("host"):
            hosts.append(str(obj["host"]))
    return list(dict.fromkeys(hosts))


def _to_http_targets(target: str, out_dir: Path) -> list[str]:
    if "://" in target:
        return [target]
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1:
            return [f"http://{net.network_address}", f"https://{net.network_address}"]
        return [f"http://{ip}" for ip in list(net.hosts())[:16]]
    except ValueError:
        pass
    subs = _load_subfinder_hosts(out_dir)
    hosts = subs if subs else [target]
    return [f"https://{h}" for h in hosts]


def _cmd_hunt(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    sub = args.hunt_cmd

    if sub == "init":
        scope = _load_scope(args.scope, args.target)
        state = init_hunt_session(out_dir, args.target, scope)
        print(
            json.dumps(
                {
                    "status": "initialized",
                    "target": state.target,
                    "classification": state.classification,
                    "pipeline": state.recommended_pipeline,
                    "actions_count": len(state.actions),
                },
                indent=2,
            )
        )
        return 0

    if sub == "plan-next":
        proposal = propose_next_action(out_dir)
        if proposal is None:
            print(json.dumps({"status": "completed", "next_action": None}))
            return 0
        print(proposal.model_dump_json(indent=2))
        return 0

    if sub == "approve":
        act = approve_action(out_dir, args.id)
        print(act.model_dump_json(indent=2))
        return 0

    if sub == "reject":
        act = reject_action(out_dir, args.id, reason=args.reason or "")
        print(act.model_dump_json(indent=2))
        return 0

    if sub == "status":
        state = load_hunt_session(out_dir)
        print(state.model_dump_json(indent=2))
        return 0

    if sub == "execute":
        try:
            act = require_approved_action(out_dir, args.id)
        except (PermissionError, KeyError) as exc:
            print(f"✗ {exc}", file=sys.stderr)
            return 1

        state = load_hunt_session(out_dir)
        scope = state.scope
        tool = act.tool
        summary = ""
        ok = True

        try:
            if tool == "subfinder":
                res = run_subfinder(act.target, scope, out_dir, approved=True)
                ok = res.status == "ok"
                summary = res.error or f"{res.status}: {len(res.items)} subdomains"
            elif tool == "httpx":
                targets = _to_http_targets(act.target, out_dir)
                res = run_httpx(targets, scope, out_dir, approved=True)
                ok = res.status == "ok"
                summary = res.error or f"{res.status}: {len(res.items)} live HTTP endpoints"
            elif tool == "nmap":
                res = run_nmap(act.target, scope, out_dir, approved=True)
                ok = res.status == "ok"
                summary = res.error or f"{res.status}: {len(res.items)} open ports"
            elif tool == "katana":
                url = _to_http_targets(act.target, out_dir)[0]
                res = run_katana(url, scope, out_dir, approved=True)
                ok = res.status == "ok"
                summary = res.error or f"{res.status}: {len(res.items)} crawled endpoints"
            elif tool == "nuclei":
                url = _to_http_targets(act.target, out_dir)[0]
                wres = run_nuclei(url, scope, out_dir, approved=True)
                ok = wres.status == "ok"
                summary = wres.error or f"nuclei recorded {len(wres.findings)} findings"
            elif tool == "dalfox":
                url = _to_http_targets(act.target, out_dir)[0]
                wres = run_dalfox(url, scope, out_dir, approved=True)
                ok = wres.status == "ok"
                summary = wres.error or f"dalfox recorded {len(wres.findings)} XSS findings"
            elif tool == "sqlmap":
                url = _to_http_targets(act.target, out_dir)[0]
                wres = run_sqlmap(url, scope, out_dir, approved=True)
                ok = wres.status == "ok"
                summary = wres.error or f"sqlmap recorded {len(wres.findings)} SQLi findings"
            elif tool == "apk_analyzer":
                apk_res = analyze_apk(Path(act.target), out_dir)
                summary = f"package={apk_res.package_name}, libs={len(apk_res.native_libs)}, secrets={len(apk_res.secrets)}"
            elif tool == "bounty_report":
                reports = generate_bounty_reports(out_dir, target=act.target)
                summary = f"generated {', '.join(p.name for p in reports.values())}"
            else:
                summary = f"Action {tool} ready for OpenCode/REA interactive execution"
        except Exception as exc:
            ok = False
            summary = f"Execution error: {exc}"

        updated = mark_action_result(out_dir, act.id, executed=ok, summary=summary)
        print(updated.model_dump_json(indent=2))
        return 0 if ok else 1

    return 1


def _cmd_recon(args: argparse.Namespace) -> int:
    if not args.approved:
        print("✗ Recon execution requires explicit operator approval (--approved).", file=sys.stderr)
        return 1
    out_dir = Path(args.out)
    scope = _load_scope(args.scope, args.target)
    results = {}
    if args.tool in ("all", "subfinder") and "://" not in args.target:
        r = run_subfinder(args.target, scope, out_dir, approved=True)
        results["subfinder"] = {"status": r.status, "count": len(r.items)}
    if args.tool in ("all", "nmap"):
        r = run_nmap(args.target, scope, out_dir, approved=True)
        results["nmap"] = {"status": r.status, "count": len(r.items)}
    if args.tool in ("all", "httpx"):
        r = run_httpx(_to_http_targets(args.target, out_dir), scope, out_dir, approved=True)
        results["httpx"] = {"status": r.status, "count": len(r.items)}
    if args.tool in ("all", "katana"):
        r = run_katana(_to_http_targets(args.target, out_dir)[0], scope, out_dir, approved=True)
        results["katana"] = {"status": r.status, "count": len(r.items)}
    print(json.dumps(results, indent=2))
    return 0


def _cmd_mobile(args: argparse.Namespace) -> int:
    res = analyze_apk(Path(args.apk), Path(args.out))
    print(
        json.dumps(
            {
                "package_name": res.package_name,
                "manifest_flags": res.manifest_flags,
                "unprotected_exported": res.unprotected_exported,
                "endpoints_count": len(res.endpoints),
                "secrets_count": len(res.secrets),
                "ghidra_targets": res.ghidra_targets,
            },
            indent=2,
        )
    )
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    outputs = generate_bounty_reports(Path(args.out), target=args.target, platform=args.platform)
    print(json.dumps({k: str(v) for k, v in outputs.items()}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raptor.py hunt",
        description="OpenRaptor Bug Bounty & Ethical Hacking orchestrator",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # hunt
    p_hunt = subparsers.add_parser("hunt", help="Resumable /hunt state machine with approval gate")
    hunt_sub = p_hunt.add_subparsers(dest="hunt_cmd", required=True)

    p_init = hunt_sub.add_parser("init", help="Initialize hunt session")
    p_init.add_argument("--target", required=True)
    p_init.add_argument("--scope", default=None)
    p_init.add_argument("--out", required=True)

    p_plan = hunt_sub.add_parser("plan-next", help="Show next pending ActionProposal")
    p_plan.add_argument("--out", required=True)

    p_app = hunt_sub.add_parser("approve", help="Approve an ActionProposal")
    p_app.add_argument("--out", required=True)
    p_app.add_argument("--id", required=True)

    p_rej = hunt_sub.add_parser("reject", help="Reject an ActionProposal")
    p_rej.add_argument("--out", required=True)
    p_rej.add_argument("--id", required=True)
    p_rej.add_argument("--reason", default="")

    p_exec = hunt_sub.add_parser("execute", help="Execute an approved ActionProposal")
    p_exec.add_argument("--out", required=True)
    p_exec.add_argument("--id", required=True)

    p_stat = hunt_sub.add_parser("status", help="Show hunt session state")
    p_stat.add_argument("--out", required=True)

    # recon
    p_recon = subparsers.add_parser("recon", help="External recon (subfinder, nmap, httpx, katana)")
    p_recon.add_argument("--target", required=True)
    p_recon.add_argument("--scope", default=None)
    p_recon.add_argument("--out", required=True)
    p_recon.add_argument("--tool", choices=["all", "subfinder", "nmap", "httpx", "katana"], default="all")
    p_recon.add_argument("--approved", action="store_true", help="Confirm operator approval")

    # mobile
    p_mobile = subparsers.add_parser("mobile", help="Android APK analyzer + Ghidra .so handoff")
    p_mobile.add_argument("--apk", required=True)
    p_mobile.add_argument("--out", required=True)

    # report
    p_report = subparsers.add_parser("report", help="Generate Bug Bounty and Pentest reports")
    p_report.add_argument("--out", required=True)
    p_report.add_argument("--target", default="target")
    p_report.add_argument("--platform", default="generic")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.mode == "hunt":
        return _cmd_hunt(args)
    if args.mode == "recon":
        return _cmd_recon(args)
    if args.mode == "mobile":
        return _cmd_mobile(args)
    if args.mode == "report":
        return _cmd_report(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
