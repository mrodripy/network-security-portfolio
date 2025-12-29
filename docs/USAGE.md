# Usage Guide

## Basic Usage

```bash
# Network discovery
python src/portfolio_scanner.py 192.168.1.0/24 --profile discovery

# Quick security assessment
python src/portfolio_scanner.py example.com --profile quick

# Vulnerability scan (requires authorization)
python src/portfolio_scanner.py 192.168.1.1 --profile vulnerability

# Custom output directory
python src/portfolio_scanner.py target.com --output /path/to/reports

Scan Profiles
Discovery (-sn)

Fast host discovery without port scanning.
Quick (-sS -T4 -F)

Fast TCP port scan of common ports.
Comprehensive (-sS -sV -sC -O -A)

Full scan with version detection, OS detection, and script scanning.
Vulnerability (-sV --script vuln,safe)

Vulnerability assessment using NSE scripts.
UDP (-sU --top-ports 100)

Scan top 100 UDP ports.
Output Files

Each scan generates:

    .txt: Raw Nmap output

    .json: Structured scan data

    .md: Markdown summary

    _report.html: Professional HTML report
