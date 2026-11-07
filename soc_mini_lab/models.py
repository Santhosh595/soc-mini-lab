"""Core data models: LogEvent, ThreatFlag, Proposal, AuditEntry.

Everything is a plain dataclass so the whole pipeline stays stdlib-only
and JSON-serializable for the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class LogEvent:
    """One parsed log line."""

    ts: str
    level: str  # DEBUG/INFO/WARN/ERROR/CRITICAL or empty
    source: str  # service that emitted it, or filename basename
    message: str
    raw: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ThreatFlag:
    """A suspicious pattern matched against a set of events."""

    rule: str
    severity: str  # low / medium / high
    message: str
    event_index: int  # index into the ingested events list
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Proposal:
    """A proposed detection (Sigma or YARA) derived from a ThreatFlag.

    Status lifecycle: proposed -> approved | rejected. Only approved
    proposals are ever "executed" (written out / acted on); rejected
    ones are recorded in the audit log and dropped.
    """

    id: str
    flag_rule: str
    format: str  # "sigma" | "yara"
    content: str
    status: str = "proposed"  # proposed | approved | rejected
    reason: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditEntry:
    """One append-only audit record. prev_hash chains entries together."""

    seq: int
    action: str  # ingest | flag | propose | approve | reject
    actor: str
    detail: str
    ts: str
    prev_hash: str = ""
    hash: str = ""

    def as_dict(self) -> dict:
        return asdict(self)
