# Security Fundamentals Scripts

Small Python scripts for turning Security+ concepts into practical exercises.

## Scripts

| Script | What it teaches | Security+ SY0-701 Domain |
| --- | --- | --- |
| [tools/subnet_calc.py](tools/subnet_calc.py) | CIDR, network addresses, broadcast addresses, host ranges | Domain 3: Security Architecture |
| [tools/hash_demo.py](tools/hash_demo.py) | Hashing, salting, avalanche effect | Domain 1: General Security Concepts |
| [tools/caesar_cipher.py](tools/caesar_cipher.py) | Substitution ciphers, frequency analysis | Domain 1: General Security Concepts |
| [tools/password_checker.py](tools/password_checker.py) | Password entropy, common-password checks | Domain 2: Threats, Vulnerabilities, and Mitigations |
| [tools/port_scanner.py](tools/port_scanner.py) | TCP three-way handshake, port states, defensive log visibility | Domain 4: Security Operations |

## Setup and test

Python 3.11 or later is required. Install the test dependency and run the
suite from the repository root:

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

## Example output

**subnet_calc.py**
```
Enter a CIDR block (e.g. 192.168.1.0/24): 192.168.1.0/24
Network address : 192.168.1.0
Broadcast       : 192.168.1.255
Usable hosts    : 192.168.1.1 - 192.168.1.254
Total hosts     : 254
```

**password_checker.py**
```
Enter a password (input is hidden):
Length: 14 characters (meets the 8-character minimum).
Estimated entropy: 91.4 bits (rough estimate only).
Demo common-password list: no exact match found.
```

**port_scanner.py**
```
python tools/port_scanner.py 127.0.0.1 --ports 440-450 --timeout 0.3

Scanning 127.0.0.1  |  ports 440-450  |  timeout 0.3s
--------------------------------------------------
  port   445  OPEN
--------------------------------------------------
Done. 1 open port(s) found.
```

```
python tools/port_scanner.py 8.8.8.8

Error: 8.8.8.8 is a public IP address. This scanner is restricted to
localhost and private networks only. Only scan systems you own or have
written permission to test.
```

## Known Limitations

- `password_checker.py` uses a two-entry demo common-password list. A
  production checker would load a file such as `rockyou.txt`.
- `port_scanner.py` accepts dotted-decimal IPv4 addresses only; hostnames
  such as `localhost` are not resolved.
- All scripts are single-threaded; scanning large port ranges is slow by design.

## AI assistance

AI assistance was used for the repository scaffold, Python test configuration,
and README formatting. The Concepts blocks and rule/check logic are written by
the project author.
