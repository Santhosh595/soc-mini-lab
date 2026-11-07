# soc-mini-lab

AI-assisted SOC mini-lab (deterministic MVP): ingests logs, flags suspicious events, proposes Sigma/YARA-style detection ideas — every action behind a human approval gate + append-only audit log.

## How it works

```
logs ──▶ ingest ──▶ flag (heuristics) ──▶ propose (Sigma/YARA) ──▶ approve/reject ──▶ audit log
```

1. **Ingest** parses plain-text, bracketed (`[ts] LEVEL service: msg`), and syslog-ish lines into `LogEvent`s.
2. **Flag** runs window/keyword heuristics: auth brute-force bursts, error bursts, possible exfiltration, privilege escalation, injection, persistence.
3. **Propose** turns each flag into a Sigma or YARA template. Proposals are *never* auto-approved or auto-executed.
4. **Approve/Reject** is a human decision (interactive prompt, `--auto-approve`, or `--auto-reject`). Approved proposals are written to `--out-dir`; rejected ones only appear in the audit log.
5. **Audit** every step (ingest, flag, propose, approve, reject) is appended to a JSONL log with a SHA-256 hash chain. `verify` walks the chain and reports the first tampered entry.

> **MVP note:** detection logic is deterministic heuristics, not an LLM call. The README's "LLM agent" vision is future work — the pipeline, approval gate, and audit log are real and tested.

## Getting Started

### Prerequisites

- Python 3.10+
- Git

### Installation

```bash
git clone https://github.com/Santhosh595/soc-mini-lab.git
cd soc-mini-lab
pip install -e .
```

### Usage

```bash
# Full pipeline (asks before approving each proposal)
soc-mini-lab run /var/log/app.log

# Non-interactive: approve everything and write approved rules to ./rules/
soc-mini-lab run /var/log/app.log --auto-approve --out-dir rules/

# Non-interactive: reject everything (dry run)
soc-mini-lab run /var/log/app.log --auto-reject

# Machine-readable output
soc-mini-lab run /var/log/app.log --json --auto-reject

# Just parse and print events (debug)
soc-mini-lab ingest /var/log/app.log

# Verify the audit log has not been tampered with
soc-mini-lab verify
```

Audit log defaults to `~/.local/share/soc-mini-lab/audit.jsonl` (`--audit` to override).

## Project layout

```
soc-mini-lab/
├── soc_mini_lab/
│   ├── cli.py          # run / ingest / verify subcommands
│   ├── ingest.py       # log-line parsers
│   ├── heuristics.py   # suspicious-event rules
│   ├── proposals.py    # Sigma/YARA template generation
│   ├── audit.py        # append-only hash-chained JSONL log
│   └── models.py       # LogEvent, ThreatFlag, Proposal, AuditEntry
├── tests/
│   ├── fixtures/       # benign.log, attack.log
│   ├── test_ingest.py
│   ├── test_heuristics.py
│   ├── test_proposals.py
│   ├── test_audit.py
│   └── test_cli.py
├── pyproject.toml
└── LICENSE             # MIT
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
