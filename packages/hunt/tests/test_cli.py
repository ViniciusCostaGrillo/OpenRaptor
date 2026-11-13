"""Tests for packages/hunt/cli.py and raptor.py hunt/recon/mobile/report dispatch."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.hunt import cli as hunt_cli


class TestHuntCli:
    def test_init_plan_approve_execute_flow(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out_dir = tmp_path / "run1"
        assert hunt_cli.main(["hunt", "init", "--target", "example.com", "--out", str(out_dir)]) == 0
        assert (out_dir / "hunt_state.json").is_file()

        assert hunt_cli.main(["hunt", "plan-next", "--out", str(out_dir)]) == 0
        out = capsys.readouterr().out
        assert "act-001" in out
        assert "subfinder" in out

        # Executing before approval must fail cleanly (exit 1)
        assert hunt_cli.main(["hunt", "execute", "--out", str(out_dir), "--id", "act-001"]) == 1

        # Approve and mock subfinder execution
        assert hunt_cli.main(["hunt", "approve", "--out", str(out_dir), "--id", "act-001"]) == 0
        monkeypatch.setattr(
            hunt_cli,
            "run_subfinder",
            lambda domain, scope, od, **kw: SimpleNamespace(tool="subfinder", status="ok", items=[{"host": "api.example.com"}], error=""),
        )
        assert hunt_cli.main(["hunt", "execute", "--out", str(out_dir), "--id", "act-001"]) == 0

    def test_raptor_py_hunt_help_exits_zero(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        proc = subprocess.run(
            [sys.executable, str(repo_root / "raptor.py"), "hunt", "--help"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert proc.returncode == 0
        assert "hunt" in proc.stdout.lower()
