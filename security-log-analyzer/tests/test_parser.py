"""Unit tests for the logan OpenSSH auth.log parser."""

from pathlib import Path
import pytest
from logan.parser import LogEvent, parse_line, parse_log


# ---------------------------------------------------------------------------
# Positive Test Cases: 6+ Distinct Line Formats
# ---------------------------------------------------------------------------

def test_parse_failed_password_valid_user() -> None:
    line = "Jan 15 03:21:04 server sshd[12345]: Failed password for root from 192.168.1.10 port 22 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.timestamp == "Jan 15 03:21:04"
    assert event.host == "server"
    assert event.process == "sshd[12345]"
    assert event.event_type == "failed_password"
    assert event.user == "root"
    assert event.src_ip == "192.168.1.10"
    assert event.port == 22
    assert event.raw == line


def test_parse_failed_password_invalid_user() -> None:
    line = "Jan 15 03:21:05 server sshd[12345]: Failed password for invalid user admin from 192.168.1.11 port 52345 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "failed_password_invalid"
    assert event.user == "admin"
    assert event.src_ip == "192.168.1.11"
    assert event.port == 52345


def test_parse_accepted_password() -> None:
    line = "Jan 15 03:21:06 server sshd[12346]: Accepted password for analyst from 192.168.1.50 port 49152 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "accepted_password"
    assert event.user == "analyst"
    assert event.src_ip == "192.168.1.50"
    assert event.port == 49152


def test_parse_accepted_publickey() -> None:
    line = "Jan 15 03:21:07 server sshd[12347]: Accepted publickey for deployer from 192.168.1.60 port 50123 ssh2: RSA SHA256:abc123xyz"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "accepted_publickey"
    assert event.user == "deployer"
    assert event.src_ip == "192.168.1.60"
    assert event.port == 50123


def test_parse_invalid_user_probe() -> None:
    line = "Jan 15 03:21:08 server sshd[12348]: Invalid user testguest from 10.0.0.99 port 41234"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "invalid_user"
    assert event.user == "testguest"
    assert event.src_ip == "10.0.0.99"
    assert event.port == 41234


def test_parse_preauth_disconnect_received() -> None:
    line = "Jan 15 03:21:09 server sshd[12349]: Received disconnect from 192.168.1.200 port 55555:11: Bye Bye [preauth]"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "preauth_disconnect"
    assert event.src_ip == "192.168.1.200"
    assert event.port == 55555


def test_parse_preauth_connection_closed() -> None:
    line = "Jan 15 03:21:10 server sshd[12350]: Connection closed by 192.168.1.201 port 55556 [preauth]"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "preauth_disconnect"
    assert event.src_ip == "192.168.1.201"
    assert event.port == 55556


def test_parse_preauth_disconnect_with_user() -> None:
    line = "Jan 15 03:21:11 server sshd[12351]: Disconnected from invalid user admin 192.168.1.202 port 55557 [preauth]"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "preauth_disconnect"
    assert event.user == "admin"
    assert event.src_ip == "192.168.1.202"
    assert event.port == 55557


def test_parse_iso8601_timestamp_format() -> None:
    line = "2026-01-15T03:21:04.123456+00:00 server sshd[12345]: Failed password for root from 192.168.1.10 port 22 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.timestamp == "2026-01-15T03:21:04.123456+00:00"
    assert event.event_type == "failed_password"


# ---------------------------------------------------------------------------
# Negative Test Cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "invalid_or_non_target_line",
    [
        "",  # Empty string
        "   \n",  # Whitespace only
        "Not a syslog format at all",  # Garbage string
        "Jan 15 03:21:11 server CRON[9999]: (root) CMD (/usr/local/bin/backup.sh)",  # CRON event
        "Jan 15 03:21:12 server sudo: analyst : TTY=pts/0 ; COMMAND=/bin/cat",  # sudo event
        "Jan 15 03:21:13 server sshd[12351]: Server listening on 0.0.0.0 port 22.",  # Non-auth sshd message
    ],
)
def test_parse_line_negative_cases(invalid_or_non_target_line: str) -> None:
    assert parse_line(invalid_or_non_target_line) is None


# ---------------------------------------------------------------------------
# Batch & Unparsed Line Counting
# ---------------------------------------------------------------------------

def test_parse_log_from_fixture() -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "synthetic_auth.log"
    with open(fixture_path, "r", encoding="utf-8") as f:
        events, unparsed = parse_log(f)

    # In synthetic_auth.log, there are 7 sshd auth events and 3 non-auth / other lines
    assert len(events) == 7
    assert unparsed == 3


# ---------------------------------------------------------------------------
# Stress Test: 10,000+ line sample execution
# ---------------------------------------------------------------------------

def test_parse_10k_lines_stress() -> None:
    """Ensure parser runs on 10,000+ lines without errors or crashing."""
    templates = [
        "Jan 15 03:21:04 server sshd[12345]: Failed password for root from 192.168.1.10 port 22 ssh2",
        "Jan 15 03:21:05 server sshd[12345]: Failed password for invalid user admin from 10.0.0.1 port 52345 ssh2",
        "Jan 15 03:21:06 server sshd[12346]: Accepted password for analyst from 192.168.1.50 port 49152 ssh2",
        "Jan 15 03:21:07 server sshd[12347]: Accepted publickey for deployer from 192.168.1.60 port 50123 ssh2: RSA SHA256:abc",
        "Jan 15 03:21:08 server sshd[12348]: Invalid user testguest from 10.0.0.99 port 41234",
        "Jan 15 03:21:09 server sshd[12349]: Received disconnect from 192.168.1.200 port 55555:11: Bye Bye [preauth]",
        "Jan 15 03:21:11 server CRON[9999]: (root) CMD (/usr/local/bin/backup.sh)",  # unparsed
        "Jan 15 03:21:13 server sshd[12351]: Server listening on 0.0.0.0 port 22.",  # unparsed
    ]

    total_lines = 12000
    generated_lines = (templates[i % len(templates)] for i in range(total_lines))

    events, unparsed = parse_log(generated_lines)

    # 6 out of 8 templates are valid auth events, 2 are unparsed
    expected_events = total_lines * 6 // 8
    expected_unparsed = total_lines * 2 // 8

    assert len(events) == expected_events
    assert unparsed == expected_unparsed
    assert all(isinstance(e, LogEvent) for e in events) # Proves every event is a proper LogEvent object
