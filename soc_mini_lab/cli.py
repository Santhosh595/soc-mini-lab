"""Command-line entry point for soc-mini-lab.

Pipeline: ingest -> flag -> propose -> approve/reject -> audit.

Subcommands:
  run       Full pipeline on a log file/dir. Writes flags + proposals,
            then asks for approval per proposal (or --auto-reject for
            non-interactive runs). Every step is audit-logged.
  verify    Walk the audit log hash chain.
  ingest    Just parse and print events (debug aid).

Nothing is ever "executed" automatically: proposals only become files
under --out-dir after an explicit approve.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .audit import AuditLog
from .heuristics import flag_events
from .ingest import ingest_path
from .models import Proposal
from .proposals import propose


def _default_audit_path() -> Path:
    return Path.home() / ".local" / "share" / "soc-mini-lab" / "audit.jsonl"


def _cmd_run(args) -> int:
    audit = AuditLog(Path(args.audit))
    try:
        events = ingest_path(Path(args.path))
    except OSError as exc:
        print(f"soc-mini-lab: cannot ingest {args.path}: {exc}", file=sys.stderr)
        return 2
    audit.append("ingest", args.actor, f"{len(events)} events from {args.path}")

    flags = flag_events(events)
    for f in flags:
        audit.append("flag", args.actor,
                     f"{f.rule} ({f.severity}) at event {f.event_index}: {f.message}")

    proposals: list[Proposal] = []
    for f in flags:
        p = propose(f, fmt=args.format)
        proposals.append(p)
        audit.append("propose", args.actor, f"{p.id} [{p.format}] for {f.rule}")

    approved: list[Proposal] = []
    rejected: list[Proposal] = []
    out_dir = Path(args.out_dir) if args.out_dir else None
    for p in proposals:
        if args.auto_reject:
            decision = "reject"
        elif args.auto_approve:
            decision = "approve"
        elif args.yes:
            decision = "approve"
        else:
            print(f"[{p.id}] approve this {p.format} proposal? [y/N] ", file=sys.stderr, end="", flush=True)
            ans = sys.stdin.readline().strip().lower()
            decision = "approve" if ans in ("y", "yes") else "reject"
        if decision == "approve":
            p.status = "approved"
            audit.append("approve", args.actor, f"{p.id} approved")
            approved.append(p)
            if out_dir:
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / f"{p.id}.{p.format}").write_text(p.content, encoding="utf-8")
        else:
            p.status = "rejected"
            audit.append("reject", args.actor, f"{p.id} rejected")
            rejected.append(p)

    if args.json:
        payload = {
            "events": len(events),
            "flags": [f.as_dict() for f in flags],
            "proposals": [
                {"id": p.id, "format": p.format, "status": p.status,
                 "flag_rule": p.flag_rule}
                for p in proposals
            ],
            "approved": len(approved),
            "rejected": len(rejected),
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"Ingested {len(events)} events, {len(flags)} flag(s), "
              f"{len(approved)} approved, {len(rejected)} rejected.")
        for f in flags:
            print(f"  [{f.severity.upper():6}] {f.rule}: {f.message}")
        if approved:
            print(f"Approved proposals written under {out_dir}." if out_dir
                  else "Approved proposals (no --out-dir; not written to disk).")
    return 0


def _cmd_verify(args) -> int:
    audit = AuditLog(Path(args.audit))
    ok, msg = audit.verify()
    print(("OK: " if ok else "BROKEN: ") + msg)
    return 0 if ok else 1


def _cmd_ingest(args) -> int:
    events = ingest_path(Path(args.path))
    for ev in events:
        print(f"{ev.ts} [{ev.level}] {ev.source}: {ev.message}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="soc-mini-lab",
        description="AI-assisted SOC mini-lab: ingest logs, flag suspicious "
                    "events, propose Sigma/YARA detections — every action "
                    "behind a human approval gate + append-only audit log.",
    )
    parser.add_argument("--version", action="version",
                        version=f"soc-mini-lab {__version__}")
    parser.add_argument("--audit", default=str(_default_audit_path()),
                        help="audit log path (default: ~/.local/share/soc-mini-lab/audit.jsonl)")
    parser.add_argument("--actor", default="operator",
                        help="actor name recorded in the audit log")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="full pipeline on a log file/dir")
    p_run.add_argument("path", help="log file or directory")
    p_run.add_argument("--format", choices=["sigma", "yara"], default="sigma")
    p_run.add_argument("--json", action="store_true")
    p_run.add_argument("--out-dir", default="",
                       help="write approved proposals here")
    p_run.add_argument("--auto-approve", action="store_true",
                       help="approve every proposal without asking")
    p_run.add_argument("--auto-reject", action="store_true",
                       help="reject every proposal without asking")
    p_run.add_argument("--yes", action="store_true",
                       help="same as --auto-approve (alias)")
    p_run.set_defaults(func=_cmd_run)

    p_verify = sub.add_parser("verify", help="verify the audit log hash chain")
    p_verify.set_defaults(func=_cmd_verify)

    p_ingest = sub.add_parser("ingest", help="parse and print events (debug)")
    p_ingest.add_argument("path")
    p_ingest.set_defaults(func=_cmd_ingest)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
