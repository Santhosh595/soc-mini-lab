"""Detection-proposal generator: ThreatFlag -> Sigma/YARA template.

Templates are intentionally simple and human-readable — the point of the
mini-lab is that a human reviews and approves the rule before it is
ever used. Nothing here connects to a live SIEM.
"""

from __future__ import annotations

import hashlib

from .models import Proposal, ThreatFlag

_SIGMA = """title: SOC Mini-Lab — {rule}
id: socminilab-{rule}
status: experimental
description: Auto-proposed from soc-mini-lab flag '{rule}' for human review.
references:
  - soc-mini-lab (local, unapproved)
logsource:
  category: auth
  product: linux
detection:
  selection:
    Message|contains:
      - 'failed password'
      - 'authentication failure'
  timeframe: 10m
  condition: selection | count() >= 5
level: {level}
falsepositives:
  - Legitimate user mistyping passwords
"""

_YARA = """rule soc_minilab_{rule}
{{
  meta:
    description = "Auto-proposed from soc-mini-lab flag '{rule}'"
    author = "soc-mini-lab (human approval required)"
    status = "proposed"
  strings:
    $a = "failed password" nocase
    $b = "authentication failure" nocase
    $c = "invalid user" nocase
  condition:
    2 of ($a, $b, $c)
}}
"""

_LEVEL = {"high": "high", "medium": "medium", "low": "low"}


def _proposal_id(flag: ThreatFlag) -> str:
    payload = f"{flag.rule}|{flag.severity}|{flag.message}"
    return "P-" + hashlib.sha256(payload.encode()).hexdigest()[:8]


def propose(flag: ThreatFlag, fmt: str = "sigma") -> Proposal:
    """Create a Proposal from one ThreatFlag. Never auto-approves."""
    fmt = fmt.lower()
    if fmt not in ("sigma", "yara"):
        raise ValueError(f"unknown proposal format: {fmt}")
    level = _LEVEL.get(flag.severity, "low")
    content = (_SIGMA.format(rule=flag.rule, level=level) if fmt == "sigma"
               else _YARA.format(rule=flag.rule))
    return Proposal(
        id=_proposal_id(flag),
        flag_rule=flag.rule,
        format=fmt,
        content=content,
        status="proposed",
    )
