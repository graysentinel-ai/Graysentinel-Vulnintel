# Changelog

All notable changes to **GRAYSENTINEL VULNINTEL** are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned for v4.1
- WebSocket upgrade (replace SSE for lower latency)
- PostgreSQL migration path (Alembic)
- Pytest test suite (500+ test cases)
- Scan diff (compare two runs)
- Scheduled scans per-target (cron)
- Slack / Teams webhook notifications
- Jira auto-ticket creation

### Planned for v4.2
- Distributed scanning (multi-worker)
- ML-based false positive filter (scikit-learn)
- Subdomain takeover detection
- Cloud storage enumeration (S3/GCS/Azure)
- Container/K8s exposure detection

### Planned for v5.0
- Multi-tenant SaaS architecture
- Compliance reports (SOC2, ISO 27001, PCI DSS)
- SBOM generation (CycloneDX)
- LLM-assisted remediation suggestions
- Helm chart + Terraform module

---

## [4.0.0] — 2025-10-17

### 🎉 Major Release — Enterprise-Grade

This is the first production-grade release with enterprise features.

### Added

#### Scanners (22 total)
- **Recon wave** (5): `dnsx`, `whois`, `crt.sh`, `wafw00f`, `headers`
- **Discovery wave** (5): `subfinder`, `amass`, `gau`, `httpx`, `whatweb`
- **Deep scan wave** (7): `naabu`, `rustscan`, `katana`, `feroxbuster`, `gobuster`, `sslscan`, `testssl`
- **Web vuln wave** (9): `nmap`, `nikto`, `cors`, `jwt`, `graphql`, `git`, `backup`, `admin`, `creds`
- **CVE scan wave** (1): `nuclei`

#### Intelligence
- CISA KEV integration (1748+ entries, daily refresh)
- NVD API v2 with CVSS v2/v3.1/v4.0 extraction
- EPSS API (Exploit Prediction Scoring System)
- CWE classification extraction
- Confidence scoring (high/medium/low based on KEV + EPSS)
- Semantic version range matching
- Cross-scanner finding deduplication (SHA-256 fingerprints)

#### Security
- 2FA (TOTP) support via `pyotp`
- API keys with SHA-256 hashing, per-user, expirable
- Account lockout (5 failed attempts → 15 min lock)
- Audit log with IP tracking
- Fernet encryption for at-rest secrets
- CSRF protection on all POST forms (Flask-WTF)
- Rate limiting (600/hour default, 20/min login)
- Session cookies with HttpOnly + SameSite=Lax

#### Performance
- **5 parallel waves** (3-5x faster than sequential)
- Background thread execution (scans continue while navigating UI)
- Real cancellation via process-group SIGKILL
- SSE live streaming (replaces polling)

#### UI
- **5D cyberpunk aesthetic** (3D tilt, animated grid, glow effects)
- Live radar animation during scans
- Floating scan widget (persists across all tabs)
- D3.js attack surface network graph (interactive)
- Real-time terminal log streaming
- Fully responsive (desktop, tablet, mobile)

#### Reporting
- Executive PDF (watermarked, corporate)
- SARIF 2.1.0 export (GitHub/CI-CD ready)
- CSV export (spreadsheet-compatible)
- Customer-safe HTML view (NDA-watermarked, redacted)
- JSON API (`/api/stats`, `/api/findings`)

#### Deployment
- Docker + docker-compose support
- Health check endpoint (`/health`)
- Graceful shutdown (SIGTERM/SIGINT)
- systemd service file
- Nginx reverse proxy config

#### Data Management
- SQLite default (single-user)
- PostgreSQL migration path (env var `VULN_DB_URL`)
- Retention policy (configurable days)
- Encrypted backups (Fernet)

### Changed

- **BREAKING:** Target URLs now preserve `scheme` + `port` + `path` (was lossy)
  - `http://host:8080` now correctly handled (was assumed HTTPS/443)
- **BREAKING:** Katana findings capped at 200 (was unlimited → DB flood)
- Nikto timeout reduced to 120s (was 5+ min)
- Default admin password changed (see `.env.example`)
- Classification banner changed to amber/red gradient (higher visibility)

### Fixed

- **Nuclei v3 JSON flag detection** — was silently using wrong flag on newer versions
- **DNSX deprecated `-json` flag** — switched to `-resp` (v1.2+ compatible)
- **Subprocess timeout** — now kills entire process group (no zombie children)
- **httpx alias conflict** — detects `httpx-toolkit` vs `httpx` automatically
- **Katana static assets** — filters `.png`, `.jpg`, `.css`, etc. from results
- **Nikto severity parsing** — was defaulting everything to "Medium"

### Security

- Default `SECRET_KEY` no longer hardcoded (uses env or random)
- Default `FERNET_SALT` now configurable via env
- Added startup warning if `VULN_SECRET_KEY` uses default value
- Removed `/admin` debug endpoint from production build

### Deprecated

- Old `_LOGIN_FAILURES` in-memory dict (replaced with DB-backed `User.failed_attempts`)
- `ScanMeta` class (replaced with plain dicts)

### Removed

- v1.x/v2.x migration scripts (breaking schema change)
- Deprecated `normalize_to_url()` (functionality merged into `parse_target()`)

### Known Issues

- SSE may not work behind aggressive corporate proxies (use polling fallback in v4.1)
- `testssl.sh` sometimes hangs on self-signed certs (120s timeout enforced)
- Rate limiter uses in-memory storage (resets on restart — Redis planned v4.1)
- No rate limit on `/api/findings` for authenticated users (could exhaust DB)

---

## [3.0.0] — 2025-10-14

### Added
- 15-scanner version (initial parallel waves)
- 5D cyberpunk UI
- CISA KEV integration
- Live progress via polling (SSE added in 4.0)

### Changed
- Sequential → parallel wave execution

### Fixed
- Nuclei timeout issues
- URL parsing edge cases

---

## [2.0.0] — 2025-10-13

### Added
- Live progress page
- Background thread scanning
- Flask-Login authentication
- SQLite database

### Changed
- Migrated from prototype to functional scanner

---

## [1.0.0] — 2025-10-12

### Added
- Initial prototype
- Basic Flask app
- Single-scanner (nmap only)
- No persistence

---

## Version Format

This project uses Semantic Versioning:

- **MAJOR** (X.0.0) — Breaking changes
- **MINOR** (0.X.0) — New features, backward-compatible
- **PATCH** (0.0.X) — Bug fixes, backward-compatible

---

## Commit Types (from Conventional Commits)

| Type | Meaning |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no logic change |
| `refactor` | Code change, no behavior change |
| `perf` | Performance improvement |
| `test` | Tests only |
| `chore` | Tooling, deps, config |
| `sec` | Security fix |

---

## Links

- [Keep a Changelog](https://keepachangelog.com/)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
