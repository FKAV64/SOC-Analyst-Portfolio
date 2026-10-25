import pytest

from subnet_calc import calculate_subnet


@pytest.mark.parametrize(
    ("cidr", "expected"),
    [
        (
            "10.0.0.0/8",
            {
                "network_address": "10.0.0.0",
                "broadcast_address": "10.255.255.255",
                "first_host": "10.0.0.1",
                "last_host": "10.255.255.254",
                "usable_hosts": 16_777_214,
            },
        ),
        (
            "172.16.0.0/16",
            {
                "network_address": "172.16.0.0",
                "broadcast_address": "172.16.255.255",
                "first_host": "172.16.0.1",
                "last_host": "172.16.255.254",
                "usable_hosts": 65_534,
            },
        ),
        (
            "192.168.1.0/24",
            {
                "network_address": "192.168.1.0",
                "broadcast_address": "192.168.1.255",
                "first_host": "192.168.1.1",
                "last_host": "192.168.1.254",
                "usable_hosts": 254,
            },
        ),
        (
            "192.168.1.0/30",
            {
                "network_address": "192.168.1.0",
                "broadcast_address": "192.168.1.3",
                "first_host": "192.168.1.1",
                "last_host": "192.168.1.2",
                "usable_hosts": 2,
            },
        ),
    ],
)
def test_calculate_subnet_returns_expected_details(cidr, expected):
    assert calculate_subnet(cidr) == expected


@pytest.mark.parametrize("cidr", ["not-a-cidr", "192.168.1.0/33", "2001:db8::/32"])
def test_calculate_subnet_rejects_invalid_or_non_ipv4_input(cidr):
    with pytest.raises(ValueError):
        calculate_subnet(cidr)
