"""Suspicious-event heuristics over ingested LogEvents.

Each rule scans the event list and returns ThreatFlags. Rules are
window-based (auth failures, error bursts) or keyword-based (exfil,
persistence). Severities follow: high = likely attack, medium =
worth a human look, low = ambient noise.
"""

from __future__ import annotations

import re
from collections import Counter, deque

from .models import LogEvent, ThreatFlag

_AUTH_FAIL_RE = re.compile(
    r"(failed password|invalid user|authentication failure|login.*fail|"
    r"unauthorized|access denied|bad password|wrong password)",
    re.IGNORECASE,
)
_EXFIL_RE = re.compile(
    r"(curl .*(?:http|ftp)|\bwget\b.*http|scp .+@|nc .+-|netcat|"
    r"exfiltrat|data.*(?:sent|uploaded|transferred)|POST .*/upload)",
    re.IGNORECASE,
)
_PRIV_ESC_RE = re.compile(
    r"(sudo .*(?:bash|sh|python|perl)|chmod \+s|setuid|sudoers|"
    r"privilege escalation|root shell|whoami.*root)",
    re.IGNORECASE,
)
_INJECTION_RE = re.compile(
    r"(\.\./|\.\.\\|;.*(?:cat|rm|nc|curl|wget)|"
    r"\|\s*(?:bash|sh|nc|curl|wget)|<\s*script|union\s+select|\bor\s+1\s*=\s*1\b)",
    re.IGNORECASE,
)
_PERSIST_RE = re.compile(
    r"(crontab|systemctl enable|launchctl|registry.*\\Run|"
    r"authorized_keys|/etc/passwd|persistence)",
    re.IGNORECASE,
)


def _window_flags(
    events: list[LogEvent],
    pattern: re.Pattern,
    rule: str,
    window: int,
    threshold: int,
    severity: str,
    message: str,
) -> list[ThreatFlag]:
    """Flag when >=threshold matches occur within any `window` events."""
    flags: list[ThreatFlag] = []
    hits: deque[int] = deque()
    for i, ev in enumerate(events):
        if pattern.search(ev.message):
            hits.append(i)
        while hits and i - hits[0] >= window:
            hits.popleft()
        if len(hits) >= threshold:
            flags.append(ThreatFlag(
                rule=rule,
                severity=severity,
                message=message,
                event_index=i,
                detail=f"{len(hits)} matches within {window} events; "
                       f"first at index {hits[0]}",
            ))
            hits.clear()  # one flag per burst, not per event
    return flags


def _keyword_flags(
    events: list[LogEvent],
    pattern: re.Pattern,
    rule: str,
    severity: str,
    message: str,
) -> list[ThreatFlag]:
    return [
        ThreatFlag(rule=rule, severity=severity, message=message,
                   event_index=i, detail=ev.message[:160])
        for i, ev in enumerate(events)
        if pattern.search(ev.message)
    ]


def flag_events(events: list[LogEvent]) -> list[ThreatFlag]:
    """Run every heuristic; return flags sorted by severity then index."""
    flags: list[ThreatFlag] = []
    flags.extend(_window_flags(
        events, _AUTH_FAIL_RE, "auth_brute_force", window=50, threshold=5,
        severity="high",
        message="Repeated authentication failures (possible brute force).",
    ))
    flags.extend(_window_flags(
        events, re.compile(r"\b(ERROR|CRITICAL|FATAL)\b", re.IGNORECASE),
        "error_burst", window=100, threshold=20,
        severity="medium",
        message="Error-level burst (possible service failure or attack side-effect).",
    ))
    flags.extend(_keyword_flags(
        events, _EXFIL_RE, "possible_exfiltration", "high",
        "Possible data exfiltration pattern in log message.",
    ))
    flags.extend(_keyword_flags(
        events, _PRIV_ESC_RE, "privilege_escalation", "high",
        "Possible privilege-escalation pattern in log message.",
    ))
    flags.extend(_keyword_flags(
        events, _INJECTION_RE, "injection_attempt", "medium",
        "Possible injection pattern (path traversal / shell / SQLi) in log message.",
    ))
    flags.extend(_keyword_flags(
        events, _PERSIST_RE, "persistence_setup", "medium",
        "Possible persistence mechanism mentioned in log message.",
    ))
    rank = {"high": 3, "medium": 2, "low": 1}
    flags.sort(key=lambda f: (-rank.get(f.severity, 0), f.event_index))
    return flags
