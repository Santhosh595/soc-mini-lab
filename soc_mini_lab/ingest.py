"""Log ingestion: parse plain-text / syslog-ish lines into LogEvents.

Recognized shapes (best-effort, first match wins):
  [2026-01-01T00:00:00] INFO  service: message
  2026-01-01 00:00:00,123 INFO service message
  <134>Jan  1 00:00:00 host service[123]: message    (syslog)
  LEVEl: message                                     (bare minimum)

Anything else becomes an event with the whole line as the message.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import LogEvent

_TS_PAT = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
_LEVELS = r"DEBUG|INFO|WARN(?:ING)?|ERROR|ERR|CRITICAL|CRIT|FATAL|NOTICE|TRACE"

_BRACKET_RE = re.compile(
    rf"^\[({_TS_PAT})\]\s+({_LEVELS})\s+([^:\s]+):\s*(.*)$",
    re.IGNORECASE,
)
_PLAIN_RE = re.compile(
    rf"^({_TS_PAT})\s+({_LEVELS})\b[\s:]+([^:\s]+)[\s:]+(.*)$",
    re.IGNORECASE,
)
_SYSLOG_RE = re.compile(
    rf"^(?:<\d+>)?(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\s+\S+\s+([^:\s\[]+)(?:\[\d+\])?:\s*(.*)$"
)
_BARE_LEVEL_RE = re.compile(rf"^({_LEVELS})\s*[:\-]\s*(.*)$", re.IGNORECASE)


def parse_line(line: str, source: str = "") -> LogEvent:
    """Parse one line. Never raises; falls back to raw message."""
    stripped = line.rstrip("\n")
    if not stripped.strip():
        return LogEvent(ts="", level="INFO", source=source, message="", raw=stripped)
    for pat, kind in ((_BRACKET_RE, "bracket"), (_PLAIN_RE, "plain"),
                      (_SYSLOG_RE, "syslog"), (_BARE_LEVEL_RE, "bare")):
        m = pat.match(stripped)
        if m:
            g = m.groups()
            if kind == "bracket" or kind == "plain":
                return LogEvent(ts=g[0], level=g[1].upper(), source=g[2], message=g[3], raw=stripped)
            if kind == "syslog":
                return LogEvent(ts="", level="INFO", source=g[1], message=g[2], raw=stripped)
            if kind == "bare":
                return LogEvent(ts="", level=g[0].upper(), source=source, message=g[1], raw=stripped)
    return LogEvent(ts="", level="INFO", source=source, message=stripped, raw=stripped)


def ingest_text(text: str, source: str = "") -> list[LogEvent]:
    """Parse multi-line text; blank lines are skipped."""
    return [parse_line(line, source) for line in text.splitlines() if line.strip()]


def ingest_file(path: Path) -> list[LogEvent]:
    """Parse a file. Unreadable files raise OSError to the caller."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return ingest_text(text, source=Path(path).name)


def ingest_path(path: Path) -> list[LogEvent]:
    """Ingest a file, or every *.log / *.txt under a directory recursively."""
    p = Path(path)
    if p.is_file():
        return ingest_file(p)
    if p.is_dir():
        events: list[LogEvent] = []
        for item in sorted(p.rglob("*")):
            if item.is_file() and item.suffix.lower() in (".log", ".txt"):
                events.extend(ingest_file(item))
        return events
    raise FileNotFoundError(str(path))
