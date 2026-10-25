# Security Fundamentals Scripts

Small Python scripts for turning Security+ concepts into practical exercises.

## Status

Stage 1 is implemented and ready for test verification.

## Scripts

| Script | Topic | Status |
| --- | --- | --- |
| `tools/subnet_calc.py` | CIDR, network addresses, broadcast addresses, and host ranges | Implemented (Stage 1) |
| `tools/hash_demo.py` | Hashing, salting, and the avalanche effect | Planned (Stage 2) |
| `tools/caesar_cipher.py` | Substitution ciphers and frequency analysis | Planned (Stage 2) |
| `tools/password_checker.py` | Password entropy and common-password checks | Planned (Stage 3) |
| `tools/port_scanner.py` | TCP connection scanning and defensive log visibility | Planned (Stage 3) |

## Setup and test

Python 3.11 or later is required. Install the test dependency and run the
suite from the repository root:

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

Run the subnet calculator and enter an IPv4 CIDR block when prompted:

```powershell
python tools/subnet_calc.py
```

## AI assistance

AI assistance was used for the repository scaffold, Python test configuration,
and README formatting. The Concepts blocks and rule/check logic are written by
the project author.
