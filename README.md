# soc-mini-lab

AI-assisted SOC mini-lab: LLM agent ingests logs, flags suspicious events, proposes Sigma/YARA-style detection ideas — every action behind a human approval gate + append-only audit log.

## Overview

This project provides a lightweight, AI-assisted SOC (Security Operations Center) mini-lab. The LLM agent ingests logs, flags suspicious events, and proposes detection ideas in Sigma/YARA-style formats. Every action is gated behind human approval, ensuring safety and control.

## Features

- **Log Ingestion**: Parse and analyze logs from various sources.
- **Suspicious Event Detection**: Flag potential security threats.
- **Detection Proposals**: Generate Sigma/YARA-style detection rules.
- **Human Approval Gate**: Every action requires explicit human approval.
- **Append-Only Audit Log**: Maintain a tamper-proof record of all actions.

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- OmniRouter (for local model support)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/Santhosh595/soc-mini-lab.git
cd soc-mini-lab
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

### Usage

1. Configure the LLM agent:

```bash
cp config.example.json config.json
# Edit config.json to set your preferences
```

2. Run the SOC mini-lab:

```bash
python -m soc_mini_lab
```

3. Follow the prompts to ingest logs, flag events, and propose detections.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
