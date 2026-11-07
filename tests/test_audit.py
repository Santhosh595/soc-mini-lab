"""Audit log: append-only chain, tamper detection."""

from __future__ import annotations

from soc_mini_lab.audit import AuditLog


class TestAuditLog:
    def test_append_and_verify(self, tmp_path):
        log = AuditLog(tmp_path / "audit.jsonl")
        log.append("ingest", "op", "10 events")
        log.append("flag", "op", "auth_brute_force")
        log.append("approve", "op", "P-123 approved")
        ok, msg = log.verify()
        assert ok, msg

    def test_hash_chain_links(self, tmp_path):
        log = AuditLog(tmp_path / "audit.jsonl")
        e1 = log.append("ingest", "op", "first")
        e2 = log.append("flag", "op", "second")
        assert e2.prev_hash == e1.hash
        assert e2.seq == 2

    def test_tamper_breaks_chain(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("ingest", "op", "first")
        log.append("flag", "op", "second")
        # Rewrite history: change the first entry's detail.
        text = path.read_text()
        path.write_text(text.replace("first", "forged", 1))
        ok, msg = log.verify()
        assert not ok, msg

    def test_resume_continues_chain(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path)
        log.append("ingest", "op", "first")
        log2 = AuditLog(path)  # reopen
        e = log2.append("flag", "op", "second")
        assert e.seq == 2
        ok, _ = log2.verify()
        assert ok
