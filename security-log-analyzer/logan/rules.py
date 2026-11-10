"""Detection rules for logan.

Each rule receives a list of LogEvent objects and returns a list of Alert objects.
Detection logic, thresholds, and severity decisions are written by the project author.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

from logan.parser import LogEvent


# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------

def parse_timestamp(ts: str) -> datetime:
    """Convert a syslog timestamp string into a Python datetime object.

    Handles:
      - Standard syslog format: 'Jan 15 03:21:04'
      - ISO 8601 format:        '2026-01-15T03:21:04.123456+00:00'

    The syslog format has no year, so we default to the current year.
    """
    # Try ISO 8601 first (has a year built in)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            pass

    # Fall back to standard syslog format (no year — use current year)
    current_year = datetime.now().year
    ts_with_year = f"{current_year} {ts}"
    return datetime.strptime(ts_with_year, "%Y %b %d %H:%M:%S")


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------
"""
rule_id R1: Brute Force
rule_id R2: Success After Failure
rule_id R3: Password Spray
rule_id R4: Root / Invalid User Attempts
rule_id R5: Off-Hours Login
"""
@dataclass
class Alert:
    """Represents a security alert raised by a detection rule."""

    rule_id: str           # "R1", "R2", "R3", "R4", or "R5"
    severity: str          # "Low", "Medium", or "High"
    src_ip: str            # IP address that triggered the alert
    first_seen: str        # timestamp string of the first suspicious event
    last_seen: str         # timestamp string of the most recent suspicious event
    evidence: list[str] = field(default_factory=list)  # raw log lines that fired the rule


# ---------------------------------------------------------------------------
# Rule stubs — detection logic written by the project author
# ---------------------------------------------------------------------------

def check_brute_force(
    events: Sequence[LogEvent],
    threshold: int = 5,
    window_seconds: int = 600,
) -> list[Alert]:
    """R1 — Brute Force: threshold+ failures from one IP within the time window.

    Severity: Low
    """
    pass  # TODO: write sliding-window detection logic here


def check_success_after_failure(
    events: Sequence[LogEvent],
    failure_threshold: int = 3,
    window_seconds: int = 900,
) -> list[Alert]:
    """R2 — Success After Failure: a login succeeds after failure_threshold failures
    from the same IP within the time window.

    Severity: High
    """
    pass  # TODO: write detection logic here


def check_password_spray(
    events: Sequence[LogEvent],
    threshold: int = 5,
    window_seconds: int = 600,
) -> list[Alert]:
    """R3 — Password Spray: one IP tries threshold+ distinct usernames within the time window.

    Severity: Low
    """
    pass  # TODO: write detection logic here


def check_root_or_invalid_user(
    events: Sequence[LogEvent],
    threshold: int = 3,
) -> list[Alert]:
    """R4 — Root / Invalid User Attempts: threshold+ failed attempts on root or
    non-existent accounts from one IP.

    Severity: Medium
    """
    # defaultdict(int) starts every new IP key at 0 automatically
    # defaultdict(list) starts every new IP key as [] automatically
    counts: defaultdict[str, int] = defaultdict(int)
    evidence: defaultdict[str, list[str]] = defaultdict(list)
    first_seen: dict[str, str] = {}
    last_seen: dict[str, str] = {}

    for event in events:
        is_target_event = (
            event.event_type in ["failed_password_invalid", "invalid_user"]
            or (event.event_type == "failed_password" and event.user == "root")
        )

        if event.src_ip and is_target_event:
            counts[event.src_ip] += 1
            evidence[event.src_ip].append(event.raw)
            if event.src_ip not in first_seen:
                first_seen[event.src_ip] = event.timestamp
            last_seen[event.src_ip] = event.timestamp  # always overwrite with latest

    alerts: list[Alert] = []
    for src_ip, count in counts.items():
        if count >= threshold:
            alerts.append(Alert(
                rule_id="R4",
                severity="Medium",
                src_ip=src_ip,
                first_seen=first_seen[src_ip],
                last_seen=last_seen[src_ip],
                evidence=evidence[src_ip],
            ))
    return alerts


def check_off_hours_login(
    events: Sequence[LogEvent],
    start_hour: int = 6,
    end_hour: int = 20,
) -> list[Alert]:
    """R5 — Off-Hours Login: a successful login occurs outside start_hour–end_hour.

    Severity: Medium
    """
    pass  # TODO: write detection logic here
