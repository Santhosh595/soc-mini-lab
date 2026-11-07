"""CLI contract: run pipeline, approval gate, audit, verify."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import FIXTURES

HERE = Path(__file__).resolve().parent


def _run_cli(args, tmp_path, stdin=None):
    env = dict(os.environ)
    src = str(HERE.parent)
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    audit = str(tmp_path / "audit.jsonl")
    proc = subprocess.run(
        [sys.executable, "-m", "soc_mini_lab", "--audit", audit,
         "--actor", "tester", *args],
        capture_output=True, text=True, env=env, input=stdin,
    )
    return proc, audit


class TestCliRun:
    def test_benign_auto_reject(self, tmp_path):
        proc, audit = _run_cli(["run", str(FIXTURES / "benign.log"),
                                "--json", "--auto-reject"], tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads(proc.stdout)
        assert data["events"] == 6
        assert data["flags"] == []
        assert Path(audit).exists()

    def test_attack_proposals_and_gate(self, tmp_path):
        out = tmp_path / "out"
        proc, audit = _run_cli(["run", str(FIXTURES / "attack.log"),
                                "--json", "--auto-approve",
                                "--out-dir", str(out)], tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads(proc.stdout)
        assert data["events"] == 12
        assert len(data["flags"]) > 0
        assert data["approved"] > 0
        # Approved proposals were written to disk.
        assert list(out.glob("*.sigma"))

    def test_reject_writes_nothing(self, tmp_path):
        out = tmp_path / "out2"
        proc, _ = _run_cli(["run", str(FIXTURES / "attack.log"),
                            "--auto-reject", "--out-dir", str(out)], tmp_path)
        assert proc.returncode == 0
        # Nothing approved => no proposal files.
        assert not list(out.glob("*")) if out.exists() else True

    def test_interactive_yes(self, tmp_path):
        proc, _ = _run_cli(["run", str(FIXTURES / "attack.log"), "--json"],
                           tmp_path, stdin="y\n" * 20)
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert data["approved"] > 0

    def test_verify_ok(self, tmp_path):
        proc, _ = _run_cli(["run", str(FIXTURES / "attack.log"),
                            "--auto-reject"], tmp_path)
        assert proc.returncode == 0
        # Reuse the same audit file for verify.
        proc2 = subprocess.run(
            [sys.executable, "-m", "soc_mini_lab",
             "--audit", str(tmp_path / "audit.jsonl"), "verify"],
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(HERE.parent)},
        )
        assert proc2.returncode == 0
        assert "OK" in proc2.stdout

    def test_missing_path_errors(self, tmp_path):
        proc, _ = _run_cli(["run", "/nonexistent/x.log", "--auto-reject"], tmp_path)
        assert proc.returncode == 2
