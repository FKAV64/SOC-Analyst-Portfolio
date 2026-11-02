# SOC Analyst Portfolio

Hands-on cybersecurity projects built alongside a Bachelor of Computer Science degree. Focus: defensive security, blue team tooling, and detection engineering. Target role: SOC Analyst.

---

## About

My security work is offensive-informed and defensive-focused: understanding how attacks work in order to detect and respond to them. The [Back_Door_Project](https://github.com/FKAV64/Back_Door_Project) repository demonstrates that — a Python reverse shell built to understand C2 communication and TCP framing, documented from the defender's perspective.

---

## Certifications

| Certification | Status | Target date |
| --- | --- | --- |
| CompTIA Security+ (SY0-701) | In progress | December 2026 |
| BTL1 — Blue Team Level 1 | Planned | April 2027 |

---

## Projects

| # | Project | What it builds | Status |
| --- | --- | --- | --- |
| 1 | [security-fundamentals](security-fundamentals/) | Python tools making Security+ concepts concrete: subnetting, hashing, ciphers, password entropy, TCP port scanning. Each script opens with a theory block written in my own words. | Active |
| 2 | security-log-analyzer | Parse `auth.log`, detect SSH brute force, password spraying and success-after-failure, output a severity report. | Planned — Oct 2026 |
| 3 | phishing-email-analyzer | Parse `.eml` files, score phishing indicators (header mismatches, SPF/DKIM failures, lookalike domains), output a defanged IOC table. | Planned — Feb 2027 |
| 4 | ioc-enrichment-cli | Query free-tier threat-intel APIs (AbuseIPDB, VirusTotal), cache results in SQLite, output a multi-source verdict report. | Planned — Mar 2027 |
| 5 | wazuh-detection-lab | Home SIEM lab with 10 attack-to-detection write-ups, custom Wazuh rules, and a purple-team write-up detecting my own Back_Door_Project. | Planned — Apr 2027 |
| 6 | pcap-anomaly-detector | Stream a packet capture and flag port scans, DNS anomalies and beaconing — stretch goal if ahead of schedule. | Planned — stretch |

Projects 2 onward will each live in their own repository. Links will appear in this table as they go live.

---

## Repository structure

```
SOC-Analyst-Portfolio/
├── security-fundamentals/     # Project 1 — active
│   ├── tools/                 # Five Python scripts with theory + implementation
│   ├── tests/                 # pytest suite
│   ├── pyproject.toml
│   └── README.md
├── 00_AGENTS.md               # Working agreement for coding agents
├── LICENSE                    # MIT
└── README.md                  # This file
```

---

## How to run security-fundamentals

Python 3.11 or later required. No third-party dependencies for the tools themselves.

```bash
git clone https://github.com/FKAV64/SOC-Analyst-Portfolio.git
cd SOC-Analyst-Portfolio/security-fundamentals

# install dev dependency (pytest only)
python -m pip install -e ".[dev]"

# run the test suite
python -m pytest

# run a tool directly
python tools/subnet_calc.py
python tools/hash_demo.py
python tools/port_scanner.py 127.0.0.1 --ports 20-100
```

The port scanner refuses public IP addresses by design. It only accepts localhost and private network ranges.

---

## AI assistance

Coding agents were used for repository scaffolding, test configuration, pyproject setup, README formatting, and code review. Theory blocks, detection logic, Concepts explanations, and all analytical decisions were written by me. Each project README documents the split in detail.

---

## Contact

- Email: [fomavalerio@gmail.com](fomavalerio@gmail.com)

---

## License

[MIT License](LICENSE)
