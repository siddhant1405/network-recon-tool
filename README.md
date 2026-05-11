# Network Recon & Vulnerability Assessment Tool

An automated network reconnaissance tool that mimics real-world pentest Phase 1 workflows - scanning hosts, detecting services, querying CVEs, and generating a professional HTML report.

---

## Tech Stack

- **Python 3** - Core scripting
- **Nmap** - Port scanning, service & OS detection
- **python-nmap** - Nmap Python wrapper
- **NVD API (NIST)** - CVE lookup against detected services
- **Jinja2** - HTML report templating
- **Kali Linux** - Development & testing environment

---

## How It Works

```
Target IP
    ↓
Nmap Scan (ports, services, OS detection)
    ↓
NVD API CVE Lookup (per detected service)
    ↓
HTML Report Generation
```

1. **scanner.py** - Runs Nmap programmatically, extracts open ports, services, versions, and OS
2. **vuln_lookup.py** - Queries NIST NVD API for known CVEs against each detected service
3. **report.py** - Renders all findings into a clean, color-coded HTML report

---

## Sample Output

| Port | Service | CVE | Severity |
|------|---------|-----|----------|
| 22/tcp | OpenSSH 10.2p1 | CVE-2000-0525 | HIGH |
| 22/tcp | OpenSSH 10.2p1 | CVE-2001-1459 | HIGH |

Generated HTML report with dark theme, color-coded severity badges (CRITICAL / HIGH / MEDIUM / LOW).

---

## Setup & Usage

**Requirements:**
- Kali Linux (Nmap pre-installed)
- Python 3.x

**Install dependencies:**
```bash
git clone https://github.com/siddhant1405/network-recon-tool.git
cd network-recon-tool
python3 -m venv venv
source venv/bin/activate
pip install python-nmap jinja2 requests
```

**Run:**
```bash
sudo venv/bin/python3 scanner.py
```

**Enter target IP when prompted. Report saved as `report.html`.**

**Open report:**
```bash
xdg-open report.html
```

---

## Project Structure

```
network-recon-tool/
├── scanner.py          # Nmap wrapper + main pipeline
├── vuln_lookup.py      # NVD API CVE lookup
├── report.py           # Jinja2 HTML report generator
└── README.md
```

---

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Only scan networks and systems you have explicit permission to test. Unauthorized scanning is illegal.

---


