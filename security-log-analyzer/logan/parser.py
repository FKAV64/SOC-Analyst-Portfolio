"""OpenSSH auth.log parsing module.

Extracts structured LogEvent records from syslog-formatted OpenSSH authentication lines.
Tracks unparsed or non-SSH lines gracefully without halting execution.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


@dataclass(frozen=True, slots=True) # frozen=True makes the dataclass immutable  and slots=True is for memory optimization.
class LogEvent:
    """Represents a normalized OpenSSH security event extracted from an auth log."""

    timestamp: str
    host: str
    process: str
    event_type: str
    user: str | None
    src_ip: str | None
    port: int | None
    raw: str


# Regex to match syslog-formatted OpenSSH auth.log lines which supports both traditional(e.g. Jan 15 03:21:04) and ISO-8601 (2026-01-15T03:21:04) timestamps.
HEADER_REGEX = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\S+))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>sshd(?:\[\d+\])?):\s+"
    r"(?P<message>.*)$"
)


def parse_line(line: str) -> LogEvent | None:
    """Parse a single auth.log line into a LogEvent dataclass.

    Returns None if the line does not match sshd format or known security events.
    """
    raw_line = line.rstrip("\r\n")
    if not raw_line:
        return None

    # Step 1: Split line into header (timestamp, host, sshd) and message body
    header_match = HEADER_REGEX.match(raw_line)
    if not header_match:
        return None # log which are not sshd are ignored here.

    timestamp = header_match.group("timestamp")
    host = header_match.group("host")
    process = header_match.group("process")
    message = header_match.group("message")

    # Step 2: Identify what kind of SSH event is it

    # Case A: Failed password for an invalid (non-existent) user
    if "Failed password for invalid user" in message:
        m = re.search(r"Failed password for invalid user (\S+) from (\S+) port (\d+)", message)
        if m:
            user = m.group(1)
            src_ip = m.group(2)
            port = int(m.group(3))
            return LogEvent(timestamp, host, process, "failed_password_invalid", user, src_ip, port, raw_line)

    # Case B: Failed password for a valid/existing user
    elif "Failed password for" in message:
        m = re.search(r"Failed password for (\S+) from (\S+) port (\d+)", message)
        if m:
            user = m.group(1)
            src_ip = m.group(2)
            port = int(m.group(3))
            return LogEvent(timestamp, host, process, "failed_password", user, src_ip, port, raw_line)

    # Case C: Successful password login
    elif "Accepted password for" in message:
        m = re.search(r"Accepted password for (\S+) from (\S+) port (\d+)", message)
        if m:
            user = m.group(1)
            src_ip = m.group(2)
            port = int(m.group(3))
            return LogEvent(timestamp, host, process, "accepted_password", user, src_ip, port, raw_line)

    # Case D: Successful public key login
    elif "Accepted publickey for" in message:
        m = re.search(r"Accepted publickey for (\S+) from (\S+) port (\d+)", message)
        if m:
            user = m.group(1)
            src_ip = m.group(2)
            port = int(m.group(3))
            return LogEvent(timestamp, host, process, "accepted_publickey", user, src_ip, port, raw_line)

    # Case E: Probe attempting a non-existent username attacker just sents names no passwords
    elif "Invalid user" in message:
        m = re.search(r"Invalid user (\S+) from (\S+)(?: port (\d+))?", message)
        if m:
            user = m.group(1)
            src_ip = m.group(2)
            port = int(m.group(3)) if m.group(3) else None
            return LogEvent(timestamp, host, process, "invalid_user", user, src_ip, port, raw_line)

    # Case F: Scanner or client disconnected before completing login
    elif "[preauth]" in message:
        # Check if an invalid or authenticating username was logged
        user_match = re.search(r"(?:invalid|authenticating) user (\S+)", message)
        user = user_match.group(1) if user_match else None

        # Extract source IP and port right before [preauth]
        ip_port_match = re.search(r"(\S+)\s+port\s+(\d+)", message)
        if ip_port_match:
            src_ip = ip_port_match.group(1)
            port = int(ip_port_match.group(2))
            return LogEvent(timestamp, host, process, "preauth_disconnect", user, src_ip, port, raw_line)

    # If the message doesn't match any known auth events,return None
    return None


def parse_log(lines: Iterable[str]) -> tuple[list[LogEvent], int]:# Iterable[str] instead of List[str] so we could pass in a file object or any iterable of strings.
    """Parse an iterable of log lines.

    Returns:
        tuple of (parsed_events, unparsed_line_count)
    """
    events: list[LogEvent] = []
    unparsed_count = 0

    for line in lines:
        event = parse_line(line)
        if event is not None:
            events.append(event)
        else:
            if line.strip():  # non-empty lines that failed to parse
                unparsed_count += 1

    return events, unparsed_count

"""
## IMPORTANT KNOWLEDGE: The unparsed_count allows us to determine how many lines in the log file were not successfully parsed into structured events. This can be useful for debugging and improving the parser.

To ensure we only deal with ssh logs in the HEADER_REGEX at the process level, we ensure we only validate sshd processes.
"""