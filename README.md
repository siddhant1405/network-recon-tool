# Network Recon & Vulnerability Assessment Tool

A Dockerized network reconnaissance dashboard for authorized security testing. It scans targets, shows exposed services, optionally checks CVE matches, and explains findings in plain language.

## Features

- Fast web-based scanning from a React dashboard
- Fast and Deep scan modes
- Open-port inventory with "What this means" summaries
- Optional CVE matching against NIST NVD data
- Optional Groq-powered AI summary with a built-in fallback
- Risk scoring by host
- Charts for severity distribution and host risk
- File upload for target lists
- Report generation and export:
  - **PDF** — structured report with executive summary, AI analysis, per-host port tables, and CVE details
  - **Excel** — multi-sheet workbook (Summary, Hosts, Ports, CVEs) with all scan data
  - **CSV** — flat export of all host, port, and CVE data
  - **Share** — copies a text summary to clipboard or uses the Web Share API

## Scan Modes

### Fast

Fast mode is the default. It is designed for day-to-day checks when you want results quickly.

Fast mode:

- Checks common reachable ports
- Skips slower OS detection
- Skips external CVE API calls
- Skips HTTP/TLS fingerprinting
- Adds a plain-language summary for every detected open port

Use Fast mode first when scanning your own machine or a small local network.

### Deep

Deep mode keeps the heavier checks for detailed review.

Deep mode:

- Runs service and version detection
- Attempts OS detection
- Performs HTTP/TLS fingerprinting where relevant
- Looks up possible CVE matches from NVD
- Adds summaries below each CVE explaining what the match means

Deep mode can take much longer because Nmap service detection, OS detection, fingerprinting, and NVD rate limits all add time.

## AI Summary

The dashboard shows an AI Summary at the top of the results.

If `GROQ_API_KEY` is configured, the app sends only a sanitized scan summary to Groq. The request includes counts, severity totals, risk labels, and service names. It does not send IP addresses, hostnames, raw banners, or full CVE descriptions.

If `GROQ_API_KEY` is not configured or the API call fails, the app uses a local fallback explanation.

## Tech Stack

- React + Vite frontend
- FastAPI backend
- Nmap via `python-nmap`
- NIST NVD API for CVE matching in Deep mode
- Groq API for optional AI explanations
- jsPDF for PDF report generation
- SheetJS (xlsx) for Excel export
- Docker Compose for local deployment

## Run With Docker

```bash
git clone https://github.com/siddhant1405/network-recon-tool.git
cd network-recon-tool
cp backend/.env.example backend/.env
docker compose up -d --build
```

Open the dashboard:

```text
http://localhost/
```

Backend API:

```text
http://localhost:8000/
```

Stop the app:

```bash
docker compose down
```

## Optional Environment Variables

Create `backend/.env` from the example file:

```bash
cp backend/.env.example backend/.env
```

Supported variables:

```bash
GROQ_API_KEY=your_groq_key
GROQ_MODEL=llama-3.3-70b-versatile
NVD_API_KEY=your_nvd_key
```

`NVD_API_KEY` is optional, but it improves NVD rate limits when using Deep mode.

## API Usage

Run a fast scan:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","scan_mode":"fast"}'
```

Run a deep scan:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","scan_mode":"deep"}'
```

Targets can be a single IP, hostname, CIDR range, or multiple targets separated by newlines or commas.

## Project Structure

```text
network-recon-tool/
├── backend/
│   ├── api.py
│   ├── scanner/
│   │   ├── ai_summary.py
│   │   ├── fingerprint.py
│   │   ├── models.py
│   │   ├── report.py
│   │   ├── risk_engine.py
│   │   ├── scanner.py
│   │   ├── utils.py
│   │   └── vuln_lookup.py
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── index.css
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

## Notes

- Fast mode is intentionally lighter so scans do not feel slow on a healthy local machine.
- CVE matches are possible matches based on detected service metadata. They are not proof that a host is exploitable.
- Deep mode may be slower when many services are discovered, especially without an `NVD_API_KEY`.
- Only scan systems and networks you own or have explicit permission to test.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized scanning may be illegal.
