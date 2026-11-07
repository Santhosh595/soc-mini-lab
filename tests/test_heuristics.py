"""Heuristics: attack log flags, benign log stays quiet."""

from __future__ import annotations

from soc_mini_lab.heuristics import flag_events
from soc_mini_lab.ingest import ingest_file

from conftest import FIXTURES


class TestAttackLog:
    def test_attack_log_flags(self):
        events = ingest_file(FIXTURES / "attack.log")
        flags = flag_events(events)
        rules = {f.rule for f in flags}
        assert "auth_brute_force" in rules
        assert "injection_attempt" in rules
        assert any(f.severity == "high" for f in flags)

    def test_flags_sorted_by_severity(self):
        flags = flag_events(ingest_file(FIXTURES / "attack.log"))
        rank = {"high": 3, "medium": 2, "low": 1}
        ranks = [rank[f.severity] for f in flags]
        assert ranks == sorted(ranks, reverse=True)


class TestBenignLog:
    def test_benign_log_no_flags(self):
        events = ingest_file(FIXTURES / "benign.log")
        assert flag_events(events) == []

    def test_single_auth_failure_no_burst_flag(self):
        # One failure is noise; five within 50 events is a burst.
        from soc_mini_lab.ingest import ingest_text
        events = ingest_text("[2026-01-01T00:00:01] INFO sshd: Failed password for root\n")
        flags = flag_events(events)
        assert not any(f.rule == "auth_brute_force" for f in flags)
