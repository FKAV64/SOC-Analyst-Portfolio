"""
## Concepts

### IPv4 addressing

IPv4 is an addressing protocol that allows computers to find and communicate
with each other across networks. An IPv4 address is a 32-bit binary number,
shown as four decimal numbers separated by dots, such as `192.168.1.10` with each section within the dots consisting of 8 bits(0-255). It
provides a logical location for a network interface, helping routers know where
to forward data.

### Subnetting and CIDR

Subnetting divides a large IP network into smaller logical networks, called
subnets. This can improve bandwidth use and help isolate critical machines.
CIDR (Classless Inter-Domain Routing) makes this possible by defining how much
of an address identifies the network and how much remains for hosts.

For example, `/24` means that the first 24 bits identify the network. The
remaining 8 host bits are available for addresses within that network.

### Important addresses in a subnet

- **Network address:** The base address of a subnet. It identifies the network
  segment for routing and is calculated by setting all host bits to `0`.
- **Broadcast address:** The highest address in a subnet. It is calculated by
  setting all host bits to `1`; data sent to it is delivered to every computer
  on that subnet.
- **Host range:** The addresses between the network and broadcast addresses.
  These identify individual computers in the subnet.
"""

import ipaddress


def calculate_subnet(cidr: str) -> dict[str, str | int]:
    """Return the key IPv4 addresses and usable-host count for a CIDR block."""
    network = ipaddress.ip_network(cidr, strict=False)

    if network.version != 4:
        raise ValueError("Only IPv4 CIDR blocks are supported.")

    if network.prefixlen == 32:
        first_host = last_host = network.network_address
        usable_hosts = 1
    elif network.prefixlen == 31:
        first_host = network.network_address
        last_host = network.broadcast_address
        usable_hosts = 2
    else:
        first_host = network.network_address + 1
        last_host = network.broadcast_address - 1
        usable_hosts = network.num_addresses - 2

    return {
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "first_host": str(first_host),
        "last_host": str(last_host),
        "usable_hosts": usable_hosts,
    }


if __name__ == "__main__":
    cidr = input("Enter an IPv4 CIDR block (for example, 192.168.1.0/24): ")

    try:
        details = calculate_subnet(cidr)
    except ValueError as error:
        print(f"Invalid input: {error}")
    else:
        for label, value in details.items():
            print(f"{label.replace('_', ' ').title()}: {value}")
