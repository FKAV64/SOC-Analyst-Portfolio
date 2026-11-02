"""
Ports: A port is a door through which any application in a computer uses to communicate on a network. A single computer has up to 65535 ports, some of which are specific to some protocols (like SSH 22, HTTPS 443) and the remaining are available to any application.

Port Scanner & TCP 3-Way Handshake: A port scanner is one which looks for listening ports. To do this, it uses the TCP 3-Way Handshake (SYN, SYN-ACK, ACK) process. The port scanner sends a SYN to all 65535 ports.

Port States: If a port is open, it will reply with a SYN-ACK indicating an application is listening at that particular port. If a port is closed, it will respond with a reset packet (RST) indicating no application is listening on that port. If we receive no response from the server, it indicates a firewall is standing in front of the server, silently dropping the SYN sent by the port scanner

Important Definations for the port scanner implementation
1. A private address(10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16) is use for Local Area Network.
2. A loopback/localhost(127.0.0.0/8) address is use for localhost.
3. A link-local address is use to assign ip address to devices should in case the DHCP(Dynamic Host Configuration Protocol) is not working. DHCP is responsible for assigning ip address to devices in a network.
"""
import ipaddress
import socket


def is_allowed_target(target_ip: str) -> bool:
    """Return True only when target_ip is a private, loopback, or link-local address.

    Raises ValueError with a human-readable message when target_ip is a
    is not a valid IP or when it is apublic IP .
    """
    try:
        ip = ipaddress.ip_address(target_ip)
    except ValueError:
        raise ValueError(
            f"'{target_ip}' is not a valid IP address. "
            "Supply a dotted-decimal IP such as 127.0.0.1 or 192.168.x.x."
        )

    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True

    raise ValueError(
        f"{target_ip} is a public IP address. "
        "This scanner is restricted to localhost and private networks only. "
        "Only scan systems you own or have written permission to test."
    )


def scan_port(target_ip: str, port: int, timeout: float = 1.0) -> str:
    """Attempt a TCP connect to target_ip:port and return the port state.
    Returns'open' or 'closed' or'filtered'
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock: #AF_INET enforces IPv4 and SOCK_STREAM enforces TCP
        sock.settimeout(timeout)
        try:
            # attempt the TCP Handshake
            result = sock.connect_ex((target_ip, port))
        except socket.timeout:
            return "filtered"

    if result == 0:
        return "open"
    return "closed"


def parse_port_range(port_range: str) -> range:
    """Parse a 'start-end' string into a range of port numbers.

    Raises ValueError when the format is wrong or ports are out of 1-65535.
    """
    try:
        start_str, end_str = port_range.split("-")
        start, end = int(start_str), int(end_str)
    except ValueError:
        raise ValueError(
            f"'{port_range}' is not a valid port range. Use the format start-end, e.g. 1-1024."
        )

    if not (1 <= start <= end <= 65535):
        raise ValueError(
            f"Port range must be between 1 and 65535. Got {start}-{end}."
        )

    return range(start, end + 1)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="TCP port scanner — private/localhost targets only."
    )
    parser.add_argument(
        "target_ip",
        help="Dotted-decimal IPv4 address to scan (e.g. 127.0.0.1).",
    )
    parser.add_argument(
        "--ports",
        default="1-1024",
        metavar="START-END",
        help="Port range to scan, inclusive (default: 1-1024).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="Seconds to wait per port before marking it filtered (default: 1.0).",
    )
    args = parser.parse_args()

    # Guard: block public IPs before any scanning begins
    try:
        is_allowed_target(args.target_ip)
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)

    # Parse the port range
    try:
        ports = parse_port_range(args.ports)
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {args.target_ip}  |  ports {args.ports}  |  timeout {args.timeout}s")
    print("-" * 50)

    open_count = 0
    for port in ports:
        state = scan_port(args.target_ip, port, args.timeout)
        if state == "open":
            print(f"  port {port:>5}  OPEN")
            open_count += 1

    print("-" * 50)
    print(f"Done. {open_count} open port(s) found.")
