# ReconStrike

An automated recon + access-check pentesting tool that chains port scanning and weak-credential detection into a single pipeline.

## ⚠️ Disclaimer

This tool is built strictly for **educational purposes**. It was developed and tested **only in an isolated lab environment** (local Docker containers running DVWA on `127.0.0.1`). Do **not** run this against any system you do not own or do not have explicit written permission to test. Unauthorized access to computer systems is illegal under the IT Act, 2000 (India) and equivalent laws elsewhere.

## What it does

ReconStrike replicates the first two phases of a real-world penetration test:

1. **Recon (Scanning)** — Uses Nmap to discover open ports on a target and identify the service/version running on each (`scanner.py`).
2. **Access Check** — Takes the discovered services and tests them against a small set of common default credentials to flag weak logins (`access_check.py`). Currently supports HTTP (form-based login, e.g. DVWA), SSH, and FTP.
3. **Pipeline** — `main.py` runs both phases back-to-back and produces a single combined JSON report.

## Why I built this

While working through PortSwigger/Web Security Academy labs on authentication and access control, I wanted to understand *how* automated tools detect these issues rather than just using existing tools like Burp Suite or Hydra. Building this helped me understand the full attacker workflow — from discovery to exploitation — and apply concepts like CSRF token handling, session management, and credential testing in real code.

## Tech Stack

- Python 3
- `python-nmap` (Nmap wrapper)
- `requests` (HTTP login testing)
- `paramiko` (SSH login testing)
- Tested against: DVWA (Docker), on Kali Linux

## Setup

```bash
git clone <your-repo-url>
cd reconstrike
python3 -m venv venv
source venv/bin/activate
pip install python-nmap requests paramiko
```

You'll also need `nmap` installed on your system (`sudo apt install nmap`), and a test target such as DVWA running locally:

```bash
sudo docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa
```

## Usage

Run the full pipeline against a target:

```bash
sudo venv/bin/python3 main.py --target 127.0.0.1
```

Optional: specify a custom port range:

```bash
sudo venv/bin/python3 main.py --target 127.0.0.1 --ports 1-5000
```

This produces:
- `scan_results.json` — raw scan output
- `access_check_results.json` — weak credential findings
- `reconstrike_report.json` — combined final report

## Sample Output

```
[VULNERABLE] admin:password worked on http://127.0.0.1:80/login.php

=== Access Check Summary ===
  Port 80 (http): Weak/default login accepted -> admin:password
```

## Roadmap / Future Improvements

- Expand credential wordlist and allow custom wordlist input
- Add more service modules (MySQL, SMB, Telnet)
- Generate a PDF/HTML report (similar to VulScan Pro)
- Add rate-limiting/delay options to avoid lockouts on real-world safe tests

## Author

Shivam Kumar Parte — Cybersecurity graduate, building toward a career in penetration testing.
