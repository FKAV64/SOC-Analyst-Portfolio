[← Back to Portfolio Overview](../README.md)

# Security Log Analyzer

## Background

Linux `/var/log/auth.log` records every login attempt to the system. Each record is a single log line containing a timestamp, hostname, process, and specific message. For example: `'Jan 15 03:21:04 server sshd[12345]: Failed password for root from 192.168.1.10 port 22 ssh2'`. We will use `auth.log` as our data source to extract the timestamp, event type, username, source IP, and port.

A brute force attack (MITRE ATT&CK T1110.001) involves targeting a single account with many password combinations to break into it. To detect this attack, we flag multiple unsuccessful login attempts targeting a single account from a single IP within a specified time window.

Password spraying (T1110.003) uses common passwords across many different accounts—usually only a few attempts per account to bypass per-account lockout controls. To detect this, we flag login attempts across multiple distinct usernames originating from a single IP.

Success After Failure is a high-severity alert. It occurs when a successful login is observed after multiple failed login events from the same IP. This indicates a potential brute force attempt that succeeded.

False Positives are legitimate activities that trigger false alerts. For example, a class of students accessing their accounts simultaneously over the same Wi-Fi network share a single external IP address via NAT, which can mimic a password spraying attack.

The Sliding Window Technique uses a Python `deque` to maintain log events. As new log events are processed, events older than our time window (e.g., 10 minutes) are dequeue, making event evaluation computationally cheap compared to rescanning the whole log file.

# Security Log Analyzer (`logan`)

A lightweight Linux `auth.log` analyzer that inspects OpenSSH authentication activity, identifies suspicious patterns, and outputs structured reports.

## Setup and test

Python 3.11 or later is required. Install the development dependency and run the test suite:

```powershell
cd security-log-analyzer
python -m pip install -e ".[dev]"
python -m pytest
```

## Project Structure

```
security-log-analyzer/
  README.md             # Project documentation and Background
  pyproject.toml        # Project configuration and test settings
  logan/
    __init__.py
    parser.py           # line -> LogEvent dataclass & parsing engine
    rules.py            # detection rules -> Alert (Stage 2)
    report.py           # JSON + HTML/Markdown output (Stage 3)
    cli.py              # CLI entry point (Stage 3)
  tests/
    fixtures/           # Synthetic logs for testing
    test_parser.py      # Unit tests for parser (Stage 1)
    test_rules.py       # Unit tests for detection rules (Stage 2)
  samples/              # Sanitized sample logs
```

## AI assistance

AI assistance was used for the repository scaffold, regex parser boilerplate, and pytest fixtures. Detection logic, sliding window implementation, the Background section, and Known Limitations are written by the project author.

