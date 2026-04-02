# Security Policy

## Scope

SEC598 Chef is a security testing tool. It is designed to run in **authorized lab environments** against systems you own or have explicit permission to test.

## Safety Features

- **Dry-run by default**: All attack operations require `--live` flag to execute
- **Group allowlist**: Caldera operations only target approved agent groups
- **Audit logging**: Every API call is recorded in JSONL format
- **No credential storage**: API keys read from environment variables, never committed

## Reporting Vulnerabilities

If you discover a security issue in SEC598 Chef itself, please report it responsibly:

1. Do **not** open a public GitHub issue
2. Email: scthornton@gmail.com
3. Include: description, reproduction steps, and impact assessment
4. Allow 72 hours for initial response

## Usage Guidelines

- Only use against systems you own or have written authorization to test
- Always run `chef recipe lint` before executing recipes in live mode
- Review the audit log after each run
- Destroy lab infrastructure when not in use (`terraform destroy`)
- Never commit `.env` files or API keys to version control
