"""Unit tests for logan detection rules."""

from logan.parser import LogEvent
from logan.rules import Alert, check_root_or_invalid_user


def make_event(
    timestamp: str = "Jan 15 03:21:04",
    host: str = "server",
    process: str = "sshd[12345]",
    event_type: str = "failed_password",
    user: str | None = "root",
    src_ip: str | None = "192.168.1.100",
    port: int | None = 22,
    raw: str = "Jan 15 03:21:04 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
) -> LogEvent:
    """Helper to quickly construct synthetic LogEvent objects for testing."""
    return LogEvent(
        timestamp=timestamp,
        host=host,
        process=process,
        event_type=event_type,
        user=user,
        src_ip=src_ip,
        port=port,
        raw=raw,
    )


# ===========================================================================
# R4: Root or Invalid User Tests
# ===========================================================================

def test_r4_root_attempts_triggers_alert() -> None:
    """Positive test: 3 failed attempts on root from one IP triggers an R4 alert."""
    events = [
        make_event(timestamp="Jan 15 03:21:01", user="root", event_type="failed_password"),
        make_event(timestamp="Jan 15 03:21:05", user="root", event_type="failed_password"),
        make_event(timestamp="Jan 15 03:21:10", user="root", event_type="failed_password"),
    ]

    alerts = check_root_or_invalid_user(events, threshold=3)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "R4"
    assert alert.severity == "Medium"
    assert alert.src_ip == "192.168.1.100"
    assert alert.first_seen == "Jan 15 03:21:01"
    assert alert.last_seen == "Jan 15 03:21:10"
    assert len(alert.evidence) == 3


def test_r4_invalid_user_attempts_triggers_alert() -> None:
    """Positive test: Probing non-existent accounts triggers an R4 alert."""
    events = [
        make_event(timestamp="Jan 15 03:20:00", user="admin", event_type="failed_password_invalid"),
        make_event(timestamp="Jan 15 03:20:02", user="test", event_type="invalid_user"),
        make_event(timestamp="Jan 15 03:20:05", user="guest", event_type="failed_password_invalid"),
    ]

    alerts = check_root_or_invalid_user(events, threshold=3)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "R4"
    assert alerts[0].severity == "Medium"
    assert len(alerts[0].evidence) == 3


def test_r4_below_threshold_does_not_trigger() -> None:
    """Negative test: Attempts below the threshold should not trigger an alert."""
    events = [
        make_event(timestamp="Jan 15 03:21:01", user="root", event_type="failed_password"),
        make_event(timestamp="Jan 15 03:21:05", user="root", event_type="failed_password"),
    ]

    alerts = check_root_or_invalid_user(events, threshold=3)
    assert len(alerts) == 0


def test_r4_normal_user_failures_do_not_trigger() -> None:
    """Negative test: Normal user password failures (e.g. analyst) are not R4 alerts."""
    events = [
        make_event(user="analyst", event_type="failed_password"),
        make_event(user="analyst", event_type="failed_password"),
        make_event(user="analyst", event_type="failed_password"),
        make_event(user="analyst", event_type="failed_password"),
    ]

    alerts = check_root_or_invalid_user(events, threshold=3)
    assert len(alerts) == 0


def test_r4_multiple_ips_split_counts_no_false_positive() -> None:
    """Negative test: Attempts split across different IPs must not aggregate together."""
    events = [
        make_event(src_ip="192.168.1.10", user="root", event_type="failed_password"),
        make_event(src_ip="192.168.1.10", user="root", event_type="failed_password"),
        make_event(src_ip="192.168.1.20", user="root", event_type="failed_password"),
        make_event(src_ip="192.168.1.20", user="root", event_type="failed_password"),
    ]

    # Neither IP reached threshold=3
    alerts = check_root_or_invalid_user(events, threshold=3)
    assert len(alerts) == 0


def test_r4_custom_threshold() -> None:
    """Verify threshold parameter is configurable."""
    events = [
        make_event(user="root", event_type="failed_password"),
        make_event(user="root", event_type="failed_password"),
    ]

    # With threshold=2, 2 events should trigger
    alerts = check_root_or_invalid_user(events, threshold=2)
    assert len(alerts) == 1
