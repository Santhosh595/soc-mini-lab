"""Ingestion: each log shape parses into a LogEvent."""

from __future__ import annotations

from pathlib import Path

from soc_mini_lab.ingest import parse_line, ingest_file, ingest_path

from conftest import FIXTURES


class TestParseLine:
    def test_bracket_shape(self):
        ev = parse_line("[2026-01-01T08:00:01] INFO  web: GET /index 200")
        assert ev.ts == "2026-01-01T08:00:01"
        assert ev.level == "INFO"
        assert ev.source == "web"
        assert "GET /index" in ev.message

    def test_plain_shape(self):
        ev = parse_line("2026-01-01 08:00:10,123 INFO api GET /api/users 200")
        assert ev.level == "INFO"
        assert ev.source == "api"

    def test_bare_level_shape(self):
        ev = parse_line("ERROR: something broke")
        assert ev.level == "ERROR"
        assert "something broke" in ev.message

    def test_unknown_shape_falls_back(self):
        ev = parse_line("just some free text line")
        assert ev.message == "just some free text line"
        assert ev.level == "INFO"

    def test_blank_line(self):
        ev = parse_line("   ")
        assert ev.message == ""


class TestIngestFile:
    def test_benign_log_ingests(self):
        events = ingest_file(FIXTURES / "benign.log")
        assert len(events) == 6
        assert any(e.level == "WARN" for e in events)

    def test_ingest_path_file_and_dir(self):
        events = ingest_path(FIXTURES / "attack.log")
        assert len(events) == 12
        # directory scan finds both .log files
        events2 = ingest_path(FIXTURES)
        assert len(events2) == 18

    def test_missing_path_raises(self):
        try:
            ingest_path(Path("/nonexistent/xyz.log"))
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("expected FileNotFoundError")
