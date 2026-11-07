"""Append-only audit log with a hash chain.

Each entry's hash covers (seq, action, actor, detail, ts, prev_hash), so
tampering with a past entry breaks every subsequent hash. verify_chain()
walks the file and reports the first broken link.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import AuditEntry


def _entry_hash(e: AuditEntry) -> str:
    payload = f"{e.seq}|{e.action}|{e.actor}|{e.detail}|{e.ts}|{e.prev_hash}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


class AuditLog:
    """JSONL append-only log. Never rewrites existing lines."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._prev = ""
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    e = json.loads(line)
                    self._seq = max(self._seq, e["seq"])
                    self._prev = e["hash"]

    def append(self, action: str, actor: str, detail: str) -> AuditEntry:
        e = AuditEntry(
            seq=self._seq + 1,
            action=action,
            actor=actor,
            detail=detail,
            ts=_now(),
            prev_hash=self._prev,
        )
        e.hash = _entry_hash(e)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(e.as_dict()) + "\n")
        self._seq = e.seq
        self._prev = e.hash
        return e

    def verify(self) -> tuple[bool, str]:
        """Walk the chain; return (ok, first-broken-message)."""
        if not self.path.exists():
            return True, "no audit log yet"
        prev = ""
        expected_seq = 1
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            entry = AuditEntry(**e)
            if entry.seq != expected_seq:
                return False, f"seq gap: expected {expected_seq}, got {entry.seq}"
            if entry.prev_hash != prev:
                return False, f"seq {entry.seq}: prev_hash mismatch"
            if entry.hash != _entry_hash(entry):
                return False, f"seq {entry.seq}: hash mismatch (tampered)"
            prev = entry.hash
            expected_seq += 1
        return True, f"{expected_seq - 1} entries intact"
