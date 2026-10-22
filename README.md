# VULNINTEL 
> **Enterprise Vulnerability Intelligence & Attack Surface Management Platform**

[![Version](https://img.shields.io/badge/version-4.0.0-22d3ee?style=flat-square)](https://github.com/graysentinel/graysentinel-vulnintel/releases)
[![Python](https://img.shields.io/badge/python-3.13-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.1+-black?style=flat-square&logo=flask)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](https://www.gnu.org/licenses/agpl-3.0)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-268BEE?style=flat-square&logo=kalilinux)](https://www.kali.org/)
[![Scanners](https://img.shields.io/badge/scanners-22-orange?style=flat-square)]()
[![Status](https://img.shields.io/badge/status-production-green?style=flat-square)]()

Self-hosted, enterprise-grade vulnerability scanner that orchestrates **22 real security tools** in parallel to discover CVEs, misconfigurations, exposed services, and attack surface across web applications, cloud infrastructure, and DNS assets.

---

## ⚠️ LEGAL WARNING — READ BEFORE USE

This is an **offensive security tool**. Use it **ONLY** on systems you own or have **explicit written authorization** to test.

**Unauthorized scanning is a criminal offense under:**

| Jurisdiction | Law | Penalty |
|---|---|---|
| 🇮🇳 India | IT Act 2000 §66, §43 | Up to 3 years imprisonment |
| 🇺🇸 USA | CFAA 18 U.S.C. §1030 | Up to 10 years imprisonment |
| 🇬🇧 UK | Computer Misuse Act 1990 | Up to 10 years imprisonment |
| 🇪🇺 EU | Directive 2013/40/EU | Criminal liability |
| 🇫🇷 France | Code Pénal Art. 323-1 | Up to 5 years + €75,000 |
| 🇦🇺 Australia | Criminal Code Act 1995 §477 | Up to 10 years imprisonment |

**Legal test targets:**
- `scanme.nmap.org` (Nmap's authorized public target)
- `testphp.vulnweb.com` (Acunetix authorized target)
- `demo.testfire.net` (IBM authorized target)
- Your own lab VMs (Metasploitable2/3, DVWA, Juice Shop, HackTheBox, TryHackMe)

**The authors accept ZERO LIABILITY for misuse.** By using this software, you accept full responsibility for legal compliance.

---

## 📋 Table of Contents

- [What is this?](#-what-is-this)
- [Features](#-features)
- [Architecture](#-architecture)
- [Integrated Scanners](#-integrated-scanners)
- [Data Sources](#-data-sources)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [Docker Deployment](#-docker-deployment)
- [Security Hardening](#-security-hardening)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Credits](#-credits)

---

## 🎯 What is this?

GRAYSENTINEL VULNINTEL is a **self-hosted vulnerability scanner** for security teams, consultancies, and enterprises. It runs 22 real security tools (nmap, nuclei, subfinder, etc.) in **5 parallel waves** to deliver:

- **Real findings** correlated against CISA KEV, NVD, and EPSS
- **Live progress** via Server-Sent Events (works while you navigate)
- **Evidence trail** with SHA-256 snapshot hashes
- **Professional reports** (PDF, SARIF, CSV, HTML)

Unlike SaaS scanners, **your data never leaves your infrastructure**. Perfect for air-gapped environments, regulated industries, and on-premises deployments.

---

## ✨ Features

### Scanning

- ✅ **22 real scanner integrations** (subprocess-based, zero mocks)
- ✅ **5 parallel waves** — 3-5x faster than sequential
- ✅ **Background execution** — scans continue while you navigate the UI
- ✅ **Live SSE streaming** — real-time log push, no polling
- ✅ **Cancellable** — kill long scans with process-group SIGKILL
- ✅ **Graceful degradation** — missing tools skip, no crash
- ✅ **Version detection** — nuclei v2/v3 flag auto-detect
- ✅ **Retry with backoff** — KEV/NVD/EPSS fetch resilience

### Intelligence

- ✅ **CISA KEV** — Known Exploited Vulnerabilities (bulk loaded, 1748+ entries)
- ✅ **NVD API v2** — CVE metadata, CVSS v2/3.1/4.0, CWE extraction
- ✅ **EPSS API** — Exploit Prediction Scoring System
- ✅ **Confidence scoring** — high/medium/low based on KEV + EPSS
- ✅ **Cross-scanner deduplication** — SHA-256 fingerprint merge
- ✅ **Semantic version comparison** — packaging.version, not lexical

### Security

- ✅ **2FA (TOTP)** — Google Authenticator compatible
- ✅ **API keys** — SHA-256 hashed, per-user, expirable
- ✅ **Role-based access** — viewer / triager / admin
- ✅ **Account lockout** — 5 attempts → 15 min lock
- ✅ **Audit log** — every state change with IP tracking
- ✅ **Fernet encryption** — secrets at rest
- ✅ **CSRF protection** — Flask-WTF on all POST forms
- ✅ **Rate limiting** — Flask-Limiter, 600/hour default

### Reporting

- ✅ **Executive PDF** — watermarked, corporate-styled
- ✅ **SARIF 2.1.0** — GitHub/CI-CD integration
- ✅ **CSV export** — spreadsheet-ready
- ✅ **Customer-safe view** — NDA watermarked, redacted
- ✅ **JSON API** — machine-readable

### UI

- ✅ **5D cyberpunk aesthetic** — 3D perspective, animated grid, glow effects
- ✅ **Live radar animation** — real-time feedback
- ✅ **Floating scan widget** — persistent indicator across all tabs
- ✅ **D3.js attack surface graph** — force-directed, interactive
- ✅ **Fully responsive** — desktop, tablet, mobile

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              INPUT: URL / IP / Domain / Hostname                │
└────────────────────────────┬────────────────────────────────────┘
                             │
                 ┌───────────▼───────────┐
                 │  ALGORITHM 1:         │
                 │  Target Classifier    │
                 └───────────┬───────────┘
                             │
        ┌────────────────────▼────────────────────┐
        │   BACKGROUND ORCHESTRATOR (ThreadPool)  │
        │   Non-blocking · Live progress · SSE    │
        └────────────────────┬────────────────────┘
                             │
   ┌─────────────────────────▼─────────────────────────────┐
   │          5 PARALLEL WAVES (ThreadPoolExecutor)        │
   ├───────────────────────────────────────────────────────┤
   │  WAVE 1 (recon):       dnsx, whois, crt.sh,           │
   │                        wafw00f, headers               │
   │                                                       │
   │  WAVE 2 (discovery):   subfinder, amass, gau,         │
   │                        httpx, whatweb                 │
   │                                                       │
   │  WAVE 3 (deep):        naabu, rustscan, katana,       │
   │                        feroxbuster, gobuster,         │
   │                        sslscan, testssl               │
   │                                                       │
   │  WAVE 4 (webvuln):     nmap, nikto, cors, jwt,        │
   │                        graphql, git, backup,          │
   │                        admin, creds                   │
   │                                                       │
   │  WAVE 5 (CVE scan):    nuclei                         │
   └─────────────────────────┬─────────────────────────────┘
                             │
        ┌────────────────────▼────────────────────┐
        │   ALGORITHM 3:                          │
        │   Dedup + KEV/NVD/EPSS Enrichment       │
        │   SHA-256 fingerprint · Confidence      │
        └────────────────────┬────────────────────┘
                             │
        ┌────────────────────▼────────────────────┐
        │   DB (SQLite/PostgreSQL)                │
        │   + SSE Stream + Dashboard + Reports    │
        └─────────────────────────────────────────┘
```

### Core Algorithms

**Algorithm 1 — Target Classifier**
```
INPUT: user_input
1. socket.inet_pton() → IPv4 or IPv6
2. startswith(http:// | https://) → URL
3. domain regex → domain
4. single-label regex → hostname
5. ELSE → invalid (rejected at route)
```

**Algorithm 2 — Wave Orchestration**
```
FOR each wave IN [recon, discovery, deep, webvuln, cve]:
  spawn N parallel scanners with ThreadPoolExecutor(max_workers=4)
  FOR each scanner result AS it completes:
    persist findings (dedup via fingerprint)
    update SSE listeners
    check cancellation flag
  IF cancelled → break and finalize
```

**Algorithm 3 — Finding Deduplication**
```
fingerprint = SHA256(scanner | target_id | endpoint | title | cve).lower()

IF fingerprint exists in DB:
  UPDATE last_seen, enrich CVSS/EPSS if missing
  RETURN existing (not new)
ELSE:
  INSERT new finding + evidence row
  RETURN finding (new)
```

**Algorithm 4 — Confidence Scoring**
```
score = 
  100 if CVE in CISA KEV
  else 80 if EPSS >= 0.5
  else 60 if has CVE + CVSS
  else 40 if scanner in (nuclei, nmap)
  else 20

confidence = "high" if score >= 60 else "medium" if >= 40 else "low"
```

---

## 🔧 Integrated Scanners

### Wave 1 — Recon

| Scanner | Binary | Timeout | Purpose |
|---|---|---|---|
| `dnsx` | `dnsx` (Go) | 60s | DNS A/AAAA/MX/TXT/NS resolution |
| `whois` | `whois` (apt) | 30s | Domain registration info |
| `crt_sh` | HTTP only | 40s | Certificate Transparency log mining |
| `wafw00f` | `wafw00f` (pipx) | 60s | WAF detection |
| `headers` | HTTP only | 30s | Security header audit |

### Wave 2 — Discovery

| Scanner | Binary | Timeout | Purpose |
|---|---|---|---|
| `subfinder` | `subfinder` (Go) | 180s | Subdomain enumeration |
| `amass` | `amass` (apt) | 300s | Passive subdomain discovery |
| `gau` | `gau` (Go) | 120s | Wayback + CommonCrawl URLs |
| `httpx` | `httpx-toolkit` (Go) | 120s | Live endpoint probing |
| `whatweb` | `whatweb` (apt) | 120s | Technology fingerprinting |

### Wave 3 — Deep Scan

| Scanner | Binary | Timeout | Purpose |
|---|---|---|---|
| `naabu` | `naabu` (Go) | 120s | Fast port scan |
| `rustscan` | `rustscan` (cargo) | 180s | Ultra-fast full port scan |
| `katana` | `katana` (Go) | 240s | Web crawler (200 cap) |
| `feroxbuster` | `feroxbuster` (apt) | 240s | Directory discovery |
| `gobuster` | `gobuster` (apt) | 240s | Directory brute force |
| `sslscan` | `sslscan` (apt) | 180s | TLS protocol audit |
| `testssl` | `testssl.sh` (apt) | 240s | Deep TLS vulnerability audit |

### Wave 4 — Web Vulnerability

| Scanner | Binary | Timeout | Purpose |
|---|---|---|---|
| `nmap` | `nmap` (apt) | 600s | Deep port + service scan |
| `nikto` | `nikto` (apt) | 120s | Web server vulnerabilities |
| `cors` | HTTP only | 30s | CORS misconfiguration |
| `jwt` | HTTP only | 30s | JWT weak algorithm check |
| `graphql` | HTTP only | 60s | GraphQL introspection |
| `git` | HTTP only | 30s | .git exposure detection |
| `backup` | HTTP only | 60s | Backup file discovery |
| `admin` | HTTP only | 120s | Admin panel enumeration |
| `creds` | HTTP only | 60s | Default credential markers |

### Wave 5 — CVE Scanning

| Scanner | Binary | Timeout | Purpose |
|---|---|---|---|
| `nuclei` | `nuclei` (apt) | 1500s | CVE + misconfig + exposure templates |

**Total:** 22 scanners across 5 waves. **8 scanners are pure-Python HTTP** (always work). **14 require external binaries.**

---

## 📡 Data Sources

| Source | API | Refresh | Purpose |
|---|---|---|---|
| **CISA KEV** | Bulk JSON | Daily 02:00 UTC | Known Exploited Vulnerabilities |
| **NVD** | REST v2 | On-demand | CVE metadata + CVSS + CWE |
| **EPSS** | REST v1 | On-demand (batch) | Exploit prediction score |
| **crt.sh** | REST | On-demand | Certificate transparency |

---

## 💾 Installation

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Kali Linux 2024+ / Debian 12+ | Kali Rolling |
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Disk | 5 GB | 20+ GB |
| Python | 3.13+ | 3.13.x |
| Network | Required for KEV/NVD/EPSS + scanning | — |

### Step 1 — Base System

```bash
sudo apt update && sudo apt install -y \
    python3.13 python3.13-venv python3.13-dev \
    git curl wget build-essential
```

### Step 2 — Scanner Binaries (Apt)

```bash
sudo apt install -y \
    nmap nikto whatweb sslscan whois dnsutils \
    golang-go nuclei gobuster feroxbuster \
    seclists cargo pipx
```

**⚠️ `seclists` is mandatory** — the `gobuster` scanner uses this hardcoded path:
`/usr/share/seclists/Discovery/Web-Content/common.txt`

### Step 3 — Go Tools

```bash
export PATH="$HOME/go/bin:$PATH"
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc

go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Step 4 — Rust & Python Tools

```bash
cargo install rustscan --locked
pipx install wafw00f
pipx ensurepath
```

### Step 5 — httpx Symlink (Kali-Specific)

```bash
# Kali ships httpx as "httpx-toolkit" to avoid Python httpx conflict
sudo ln -sf /usr/bin/httpx-toolkit /usr/local/bin/httpx

# Verify
python3 -c "import shutil; print(shutil.which('httpx'))"
# Expected: /usr/local/bin/httpx
```

### Step 6 — Nuclei Templates (Critical)

```bash
nuclei -update-templates

# Verify
ls ~/.local/nuclei-templates/cves/ | head -5
```

**Without templates, nuclei returns 0 findings.** This is a common gotcha.

### Step 7 — Application Setup

```bash
cd ~/Desktop
git clone https://github.com/YOUR_USERNAME/graysentinel-vulnintel.git
cd graysentinel-vulnintel

python3.13 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Initialize database
python vuln_dashboard.py --init-db
```

### Step 8 — Verify All Tools

```bash
which nmap nuclei nikto whatweb sslscan whois \
      dnsx subfinder amass gau httpx naabu katana \
      feroxbuster gobuster rustscan testssl.sh wafw00f

# Expected: all 20 paths printed
```

---

## 🚀 Quick Start

```bash
cd graysentinel-vulnintel
source .venv/bin/activate

# Start server
python vuln_dashboard.py --host 127.0.0.1 --port 5000

# Open browser
# http://127.0.0.1:5000
```

**Default credentials:**

| Username | Password |
|---|---|
| `admin` | `Graysentinel@2025` |

**⚠️ CHANGE IMMEDIATELY** — via `/admin` → Create User, or env var `VULN_ADMIN_PASS`.

### First Scan

1. **Targets** → **Add Target**
2. Enter: Name=`Example`, Input=`scanme.nmap.org` (authorized legal target)
3. Click **ADD**
4. Click **▶ SCAN**
5. Watch live progress with radar + log stream
6. Click **Findings** when complete

**Expected scan time:** 2-5 minutes for a small target.

---

## ⚙️ Configuration

All configuration via environment variables. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VULN_HOST` | `127.0.0.1` | Bind address (use `0.0.0.0` for external access) |
| `VULN_PORT` | `5000` | HTTP port |
| `VULN_DB` | `vulnintel.db` | SQLite database path |
| `VULN_LOG_DIR` | `logs` | Log directory |
| `VULN_SECRET_KEY` | `dev-key` | **Flask secret — CHANGE IN PROD** |
| `VULN_FERNET_SALT` | `dev-salt` | **Encryption salt — CHANGE IN PROD** |
| `VULN_ADMIN_USER` | `admin` | Bootstrap admin username |
| `VULN_ADMIN_PASS` | `Graysentinel@2025` | **Bootstrap admin password — CHANGE IN PROD** |
| `VULN_RETENTION_FINDINGS` | `365` | Days to retain findings |
| `VULN_RETENTION_EVIDENCE` | `90` | Days to retain raw evidence |
| `VULN_SCAN_INTERVAL_HOURS` | `6` | Scheduled scan interval |

### Generate Strong Secrets

```bash
# VULN_SECRET_KEY (48+ chars)
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'

# VULN_FERNET_SALT
python3 -c 'import secrets; print(secrets.token_urlsafe(24))'

# VULN_ADMIN_PASS
python3 -c 'import secrets; print(secrets.token_urlsafe(16))'
```

Save these in `.env` (never commit) or a secret manager.

---

## 📖 Usage

### CLI Options

```bash
python vuln_dashboard.py [OPTIONS]

OPTIONS:
  --host HOST          Bind address (default: 127.0.0.1)
  --port PORT          HTTP port (default: 5000)
  --debug              Enable Flask debug mode
  --init-db            Initialize database + bootstrap admin + load KEV
  --no-scheduler       Disable APScheduler (dev mode)
```

### Common Commands

```bash
# Fresh install
python vuln_dashboard.py --init-db

# Dev server (no scheduler)
python vuln_dashboard.py --host 127.0.0.1 --port 5000 --no-scheduler

# Production server
python vuln_dashboard.py --host 0.0.0.0 --port 5000
```

### Workflow

1. **Add target** → `/targets`
2. **Trigger scan** → click `▶ SCAN`
3. **Monitor** → `/targets/<id>/progress` (live SSE)
4. **Review findings** → `/findings`
5. **Export report** → `/reports/export/pdf`

### Endpoints

| Route | Access | Description |
|---|---|---|
| `/` | Auth | Redirects to `/dashboard` |
| `/login` | Public | Login page |
| `/dashboard` | Auth | KPI overview |
| `/targets` | Admin/Triager | Target management |
| `/targets/<id>/scan` | Admin/Triager (POST) | Trigger scan |
| `/targets/<id>/progress` | Auth | Live progress (SSE) |
| `/targets/<id>/cancel` | Admin/Triager (POST) | Cancel scan |
| `/findings` | Auth | Findings list with filters |
| `/findings/<id>` | Auth | Detail view with evidence |
| `/graph` | Auth | Attack surface D3 graph |
| `/kev` | Auth | CISA KEV matches |
| `/cve` | Auth | CVE database query |
| `/admin` | Admin | Users, API keys, audit log |
| `/health` | Public | Health check (monitoring) |
| `/reports/export/csv` | Auth | CSV export |
| `/reports/export/sarif` | Auth | SARIF 2.1.0 export |
| `/reports/export/pdf` | Auth | Executive PDF |
| `/evidence/customer-safe` | Auth | Redacted NDA view |

---

## 🔌 API Reference

### Authentication

API endpoints require `X-API-Key` header. Generate keys in `/admin` → **API KEYS** → **GENERATE**.

```bash
# Create key
# → UI shows: gsk_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890

# Use in requests
curl -H "X-API-Key: gsk_..." http://127.0.0.1:5000/api/stats
```

### Endpoints

#### `GET /api/stats`

Dashboard summary metrics.

**Response:**
```json
{
  "findings": 142,
  "kev": 8,
  "targets": 5,
  "kev_stale": false
}
```

#### `GET /api/findings`

List latest 500 findings.

**Response:**
```json
[
  {
    "id": 1,
    "cve_id": "CVE-2024-3094",
    "title": "XZ Utils backdoor",
    "severity": "Critical",
    "cvss_score": 10.0,
    "epss_score": 0.94,
    "confidence": "high",
    "kev_status": true,
    "status": "new",
    "scanner": "nuclei",
    "endpoint": "https://target.com",
    "port": 443
  }
]
```

#### `GET /health`

Public health check for monitoring (no auth required).

**Response:**
```json
{
  "status": "ok",
  "version": "4.0.0",
  "database": "ok",
  "kev_stale": false,
  "active_scans": 2,
  "timestamp": "2025-10-17T12:34:56+00:00"
}
```

#### `GET /api/scan-status/<target_id>`

Live scan state for a target.

**Response:**
```json
{
  "status": "running",
  "started_at": "2025-10-17T12:30:00+00:00",
  "current_scanner": "nuclei",
  "scanners": {
    "dnsx": "success",
    "whois": "success",
    "nuclei": "running"
  },
  "findings_count": 47,
  "log": ["[12:30:01] Scan start..."]
}
```

#### `GET /api/scan-stream/<target_id>`

Server-Sent Events stream of live scan updates. Events include `type: log`, `type: scanner`, `type: state`.

```bash
curl -N -H "Cookie: session=..." \
     http://127.0.0.1:5000/api/scan-stream/1

# Output:
# data: {"type":"log","msg":"[12:30:01] Scan start..."}
# data: {"type":"scanner","scanner":"dnsx","state":"running"}
```

---

## 🐳 Docker Deployment

### Build & Run

```bash
docker build -t vulnintel:4.0.0 .
docker run -d \
  --name vulnintel \
  -p 5000:5000 \
  -e VULN_SECRET_KEY="$(openssl rand -base64 48)" \
  -e VULN_ADMIN_PASS="$(openssl rand -base64 16)" \
  -v "$(pwd)/data:/app/data" \
  vulnintel:4.0.0
```

### Docker Compose

```yaml
version: '3.8'

services:
  vulnintel:
    build: .
    ports: ["5000:5000"]
    environment:
      - VULN_SECRET_KEY=${VULN_SECRET_KEY}
      - VULN_ADMIN_PASS=${VULN_ADMIN_PASS}
      - VULN_HOST=0.0.0.0
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

```bash
docker-compose up -d
```

**Note:** Docker image is **~2.5 GB** because it includes all 22 scanners + Go/Rust toolchains.

---

## 🔒 Security Hardening

### Production Checklist

- [ ] **Change `VULN_SECRET_KEY`** — `openssl rand -base64 48`
- [ ] **Change `VULN_FERNET_SALT`** — `openssl rand -base64 24`
- [ ] **Change `VULN_ADMIN_PASS`** — 16+ chars random
- [ ] **Enable HTTPS** — nginx/caddy with Let's Encrypt
- [ ] **Restrict `/admin`** — IP whitelist or SSO
- [ ] **Enable 2FA** — for all admin accounts
- [ ] **Rate limit** — tune `600/hour` if behind CDN
- [ ] **Database backup** — nightly encrypted dumps
- [ ] **Audit log review** — weekly
- [ ] **Keep tools updated** — `nuclei -update-templates` weekly
- [ ] **Run isolated** — no public internet exposure of scanner
- [ ] **Separate worker** — for high-volume scanning, use dedicated VM

### Nginx Reverse Proxy (HTTPS)

```nginx
server {
    listen 443 ssl http2;
    server_name vulnintel.example.com;

    ssl_certificate /etc/letsencrypt/live/vulnintel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vulnintel.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # SSE support
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 3600s;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### systemd Service

```ini
# /etc/systemd/system/vulnintel.service
[Unit]
Description=GRAYSENTINEL VULNINTEL
After=network.target

[Service]
Type=simple
User=vulnintel
WorkingDirectory=/opt/vulnintel
EnvironmentFile=/opt/vulnintel/.env
ExecStart=/opt/vulnintel/.venv/bin/python vuln_dashboard.py --host 127.0.0.1 --port 5000
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vulnintel
```

---

## 🐛 Troubleshooting

### Scanner Shows MISSING

**Symptom:** Dashboard **TOOLS** panel shows scanner as `MISSING`.

**Fix:** Verify binary is on `PATH`:

```bash
which <scanner_name>

# If empty, install it. Common fixes:
export PATH="$HOME/go/bin:$PATH"  # Go tools
pipx ensurepath                    # pipx tools
source ~/.zshrc                    # Reload shell
```

### httpx Fails Silently

**Symptom:** `httpx` scanner shows `failed` with no clear error.

**Fix:** Verify symlink (Kali-specific issue):

```bash
sudo ln -sf /usr/bin/httpx-toolkit /usr/local/bin/httpx
python3 -c "import shutil; print(shutil.which('httpx'))"
# Expected: /usr/local/bin/httpx
```

### Nuclei Returns 0 Findings

**Symptom:** Nuclei scanner reports `success — 0 hits` even against vulnerable targets.

**Fix:** Install templates:

```bash
nuclei -update-templates
ls ~/.local/nuclei-templates/cves/ | head -5
```

### DNSX Shows "degraded"

**Symptom:** dnsx scanner completes but finds nothing.

**Fix:** Version compatibility — `-resp` flag used in code. If dnsx is very old:

```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

### gobuster Fails "wordlist missing"

**Symptom:** gobuster scanner fails with `wordlist missing`.

**Fix:** Install seclists:

```bash
sudo apt install -y seclists
ls /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Port 5000 Already in Use

```bash
sudo lsof -i :5000
# Or use different port:
python vuln_dashboard.py --port 5001
```

### `database is locked` Errors

**Symptom:** SQLite errors during concurrent scans.

**Fix:** Use `--no-scheduler` for dev, or migrate to PostgreSQL (see ROADMAP).

### Login Fails "Access denied"

**Fix:** Reset DB and re-bootstrap:

```bash
rm -f vulnintel.db
python vuln_dashboard.py --init-db
```

---

## 🗺 Roadmap

### v4.1 (Next)
- [ ] WebSocket upgrade (replace SSE)
- [ ] PostgreSQL migration path (Alembic)
- [ ] Pytest test suite (500+ cases)
- [ ] Scan diff (compare runs)
- [ ] Scheduled scans per-target (cron)
- [ ] Slack/Teams webhook notifications

### v4.2
- [ ] Distributed scanning (multi-worker)
- [ ] ML false-positive filter (scikit-learn)
- [ ] Subdomain takeover detection
- [ ] Cloud storage enumeration (S3/GCS/Azure)
- [ ] Container/K8s exposure detection

### v5.0
- [ ] Multi-tenant SaaS architecture
- [ ] Compliance reports (SOC2, ISO 27001, PCI DSS)
- [ ] SBOM generation (CycloneDX)
- [ ] LLM-assisted remediation
- [ ] Helm chart + Terraform module
- [ ] Mobile app (React Native)

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guide.

### Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/graysentinel-vulnintel.git
cd graysentinel-vulnintel
git checkout -b feature/your-feature
# make changes
python -m py_compile vuln_dashboard.py
git commit -m "feat: your feature"
git push origin feature/your-feature
# Open PR
```

### Code Standards

| Rule | Requirement |
|---|---|
| Python | 3.13+ |
| Line length | Max 100 chars |
| Type hints | Required |
| Docstrings | Required |
| Tests | Required for new scanners |
| No placeholders | No TODO, NotImplementedError |
| No mocks | Real subprocess only |

### Adding a Scanner

1. Create `scan_your_tool(target, timeout=None) -> Tuple[List[Dict], Dict]`
2. Return list of findings + meta (`status`, `error_log`)
3. Each finding needs: `cve_id`, `title`, `severity`, `description`, `remediation`, `endpoint`, `scanner`, `raw`
4. Register in `PIPELINE` list
5. Add to appropriate `_run_wave` in `run_full_scan()`
6. Add to `tools` dict in `dashboard()` route
7. Test on `scanme.nmap.org`
8. Update `docs/scanners.md`

---

## 📄 License

**GNU Affero General Public License v3.0 (AGPL-3.0)**

Copyright © 2025 Graysentinel Cyber Defence Lab

This program is free software: you can redistribute it and/or modify it under the terms of the AGPL-3.0 as published by the Free Software Foundation.

**AGPL-3.0 means:**
- ✅ You can use, modify, distribute freely
- ✅ You can use commercially
- ⚠️ **If you offer it as a service** (SaaS), you **MUST open-source your modifications**

Full license text: [LICENSE](LICENSE) · [gnu.org/licenses/agpl-3.0](https://www.gnu.org/licenses/agpl-3.0)

**Additional Legal Notice:** See the [LEGAL WARNING](#️-legal-warning--read-before-use) section. Unauthorized scanning is prohibited. Authors accept zero liability for misuse.

---

## 👥 Credits

| Role | Name |
|---|---|
| **Code Architect** | Ritik Shrivas |
| **Utilities Developer** | Aabhansh Gupta |
| **QA Tester** | Tanushka Kumbhar |
| **Proof of Concept** | Syed Ishrathullah |

**Vendor:** Graysentinel Cyber Defence Lab  
**Classification:** PUBLIC OPEN SOURCE — AGPL-3.0  
**Contact:** graysentinel.ai@gmail.com 
**Version:** 4.0.0  
**Last Updated:** 2026-10-17

---

## 🙏 Acknowledgments

- **CISA** for the Known Exploited Vulnerabilities catalog
- **NIST** for the National Vulnerability Database
- **FIRST** for the EPSS scoring system
- **ProjectDiscovery** for nuclei, subfinder, httpx, naabu, katana, dnsx, gau
- **Rapid7** for nmap
- **Offensive Security** for Kali Linux and seclists

**⭐ If this tool saves you time, star the repo. It helps others find it.**

**⚠️ Use responsibly. Legal authorization is your responsibility.**
