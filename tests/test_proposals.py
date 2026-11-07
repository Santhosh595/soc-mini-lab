"""Proposals: Sigma/YARA templates; never auto-approved."""

from __future__ import annotations

from soc_mini_lab.models import ThreatFlag
from soc_mini_lab.proposals import propose


class TestPropose:
    def test_sigma_template(self):
        flag = ThreatFlag(rule="auth_brute_force", severity="high",
                          message="x", event_index=0)
        p = propose(flag, fmt="sigma")
        assert p.format == "sigma"
        assert p.status == "proposed"
        assert "auth_brute_force" in p.content
        assert "level: high" in p.content

    def test_yara_template(self):
        flag = ThreatFlag(rule="injection_attempt", severity="medium",
                          message="x", event_index=0)
        p = propose(flag, fmt="yara")
        assert "rule soc_minilab_injection_attempt" in p.content

    def test_bad_format_raises(self):
        flag = ThreatFlag(rule="x", severity="low", message="x", event_index=0)
        try:
            propose(flag, fmt="suricata")
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")

    def test_ids_stable(self):
        flag = ThreatFlag(rule="auth_brute_force", severity="high",
                          message="x", event_index=0)
        assert propose(flag, "sigma").id == propose(flag, "sigma").id
