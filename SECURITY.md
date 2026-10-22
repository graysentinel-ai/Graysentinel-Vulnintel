# Security Policy

## ⚠️ This is an Offensive Security Tool

VULNINTEL performs active network scanning, port enumeration,
and vulnerability exploitation checks. **Use ONLY on systems you own or
have explicit written permission to test.**

Unauthorized scanning is illegal in most jurisdictions. See the
[LEGAL WARNING](README.md#️-legal-warning--read-before-use) in the README.

## Reporting a Vulnerability in VULNINTEL Itself

If you discover a security vulnerability **in this tool's code**, please:

**🚫 DO NOT open a public GitHub issue.**

Instead, email: **security@graysentinel.example**

Include:
- Description of vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (optional)
- Your name/handle for credit (optional)

**Expected response time:** 72 hours

### Disclosure Timeline

| Phase | Duration |
|---|---|
| Initial acknowledgment | 72 hours |
| Investigation + fix | 7-30 days (severity dependent) |
| Public disclosure | After fix released + 30-day grace |

We follow **coordinated disclosure** guidelines per [ISO/IEC 29147](https://www.iso.org/standard/72311.html).

## Supported Versions

| Version | Supported | Notes |
|---|---|---|
| 4.x | ✅ Active | Full support, security patches |
| 3.x | ⚠️ Critical only | No new features |
| < 3.x | ❌ EOL | Upgrade recommended |

## Security Architecture

### Implemented Controls

- ✅ **Authentication** — Flask-Login with bcrypt password hashing
- ✅ **2FA** — TOTP (RFC 6238) via pyotp
- ✅ **RBAC** — viewer / triager / admin roles
- ✅ **CSRF** — Flask-WTF on all POST forms
- ✅ **Rate limiting** — Flask-Limiter (600/hr default, 20/min login)
- ✅ **Session cookies** — HttpOnly, SameSite=Lax
- ✅ **Encryption** — Fernet (AES-128-CBC) for at-rest secrets
- ✅ **API keys** — SHA-256 hashed, per-user, expirable
- ✅ **Account lockout** — 5 failed attempts → 15 min
- ✅ **Audit logging** — every state change with IP
- ✅ **Input sanitization** — regex whitelist on all user input
- ✅ **SQL injection prevention** — SQLAlchemy ORM, parameterized queries
- ✅ **XSS prevention** — Jinja2 autoescape
- ✅ **Subprocess isolation** — process-group kill on timeout
- ✅ **Command injection prevention** — list-form subprocess, no shell=True

### Known Limitations

1. **SQLite by default** — single-user file DB. Use PostgreSQL for multi-user.
2. **No HTTPS by default** — deploy behind nginx/caddy with valid cert.
3. **Default admin password** — `Graysentinel@2025` — MUST change on first login.
4. **Scanner binaries** — installed separately; supply chain is user's responsibility.
5. **No built-in VPC isolation** — run on isolated VM/container.
6. **In-memory rate limiter** — resets on restart; use Redis for persistence.
7. **No WAF for scanner app itself** — add Cloudflare/ModSecurity in prod.
8. **SSE, not WebSocket** — some corporate proxies may buffer SSE streams.

### Threat Model

| Threat | Mitigation |
|---|---|
| Unauthorized scan initiation | Auth required + RBAC |
| Data exfiltration via API | API key auth + rate limit |
| Credential theft | bcrypt + 2FA + lockout |
| Secret leakage in logs | Structured logging, no secrets logged |
| SQL injection | SQLAlchemy ORM |
| XSS in findings | Jinja2 autoescape |
| CSRF | Flask-WTF tokens |
| SSRF via target URL | Input validation, DNS resolution |
| Command injection | subprocess list-form |
| Resource exhaustion | Rate limit + per-scanner timeout |

## Production Deployment Checklist

Before deploying to production, verify:

- [ ] `VULN_SECRET_KEY` changed (48+ random chars)
- [ ] `VULN_FERNET_SALT` changed (24+ random chars)
- [ ] `VULN_ADMIN_PASS` changed (16+ chars, strong)
- [ ] HTTPS enabled (nginx/caddy + Let's Encrypt)
- [ ] `/admin` IP-restricted or behind SSO
- [ ] 2FA enabled on all admin accounts
- [ ] Database backups configured (encrypted)
- [ ] Log aggregation configured (ELK/Loki)
- [ ] Monitoring configured (`/health` alerts)
- [ ] Firewall rules — only 443 exposed externally
- [ ] Scanner VM isolated from production network
- [ ] `nuclei -update-templates` cron scheduled
- [ ] Audit log reviewed weekly
- [ ] Rate limits tuned for expected load
- [ ] CSRF, CSP, HSTS headers verified

## Scanner Supply Chain

VULNINTEL calls external binaries via subprocess. You are responsible for:

- Verifying binary integrity (checksums, signatures)
- Pinning versions in production (`apt-mark hold`, `go install @version`)
- Reviewing upstream tool CVEs
- Monitoring for malicious templates (nuclei)

**Recommended:**
```bash
# Pin nuclei templates to a known-good release
git -C ~/.local/nuclei-templates checkout v9.x.x

# Verify tool signatures where available
dpkg -V nmap nuclei nikto
