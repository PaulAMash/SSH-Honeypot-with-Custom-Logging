# SSH Honeypot with Custom Logging

This project accompanies the deployment of a Cowrie SSH honeypot.

## Components

- **parse_logs.py**: Python script to parse `cowrie.json` logs and summarize:
  - Top attacker IPs
  - Most common commands
  - Downloaded payloads

## Usage

1. Deploy Cowrie honeypot on Linux VM.
2. Ensure Cowrie logs JSON entries to `cowrie.json`.
3. Run log parser:
   ```bash
   python3 parse_logs.py --logfile /path/to/cowrie.json --output summary.txt
   ```
4. Review `summary.txt` for attack patterns.

## Outputs

- `summary.txt`: Human-readable summary report.
