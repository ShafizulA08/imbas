# IMBAS — local attack-surface dashboard

<p align="center">
  <img src="assets/logo.png" width="220" alt="IMBAS logo">
</p>

A self-contained local web app for authorized reconnaissance: add a target
domain, launch a scan pipeline, watch it run live, and export findings.
*Imbas* is the Old Irish word for inspired insight — what reconnaissance
is supposed to produce.

**Authorized targets only.** Point it at domains you own or have written
permission to test.

## Quick start

```bash
cd imbas
./run.sh          # creates .venv on first run, starts on http://127.0.0.1:8000
```

Open http://127.0.0.1:8000.

## Scan pipeline

| Module    | What it does                                                        |
|-----------|---------------------------------------------------------------------|
| `rdap`    | Domain intelligence via RDAP (registrar, expiry, nameservers, status) |
| `discovery` | Subdomain enumeration: crt.sh certificate transparency + DNS brute force (~180-word built-in list, wildcard-aware) |
| `dns`     | DNS records per host (A/AAAA/CNAME/MX/NS/TXT/SOA) via dnspython     |
| `ports`   | Port scan with nmap (`-sT` connect scan, top-N ports, XML-parsed); pure-Python async connect scan fallback |
| `http`    | HTTP/HTTPS probing: status, title, server, tech fingerprints, TLS issuer + expiry, redirect chains |
| `wayback` | Historical URL discovery via the Wayback CDX API, with sensitive-path flagging (backups, configs, admin panels, dumps…) |
| `content` | Deep content analysis: sensitive-path probing (`.git/HEAD`, `.env`, Spring actuator, swagger, phpinfo, H2 console…), CORS misconfiguration checks (wildcard + origin reflection), robots.txt path mining, security.txt |
| `takeover` | Subdomain takeover detection: 22 third-party-service CNAME fingerprints (Heroku, GitHub Pages, Azure, S3, CloudFront, GCS, Shopify…) with HTTP not-found-page confirmation (critical) vs. dangling CNAME (high) |
| `cve` | Known-vulnerability matching: detected versions from Server/X-Powered-By headers, tech fingerprints and port banners checked against a bundled catalog of ~20 high-profile CVEs (Apache traversal, regreSSHion, Ghostcat, Heartbleed, Struts, Drupalgeddon, Jenkins, Exim, vsftpd…) |
| `secrets` | JavaScript/HTML secret scanning — 18 provider-specific patterns (AWS, GitHub, OpenAI, Slack, Stripe, SendGrid, private keys, JWTs…) with placeholder/entropy false-positive suppression, plus email harvesting |
| `emailsec`| Email security posture from DNS: SPF (missing / `+all` fail-open / `~all` softfail / RFC-7208 10-lookup PermError, follows `redirect=` chains), DMARC (missing / `p=none` / `pct<100` / missing `rua`/`sp`), DKIM common-selector probing (empty-key aware), MTA-STS (DNS record + policy file validation) |
| `analysis`| Findings synthesis: security-header scoring (8 headers), exposed risky services, TLS expiry, cookie security flags (Secure/HttpOnly/SameSite), default pages, version disclosure |

## Scan diffing

Compare any two scans of the same target (`⇄ Diff with…` on a completed scan)
to see new/removed hosts, open ports, live endpoints (including status
changes), secrets, findings (new vs. resolved) and harvested emails — useful
for continuous monitoring of what changed on a perimeter.

## Recurring scans & webhook alerts

Any target can be put on a schedule (`⏱ Schedule` button): pick an interval
(hours) and an optional webhook URL. The built-in scheduler wakes every 30s,
launches due scans (deferring if the target already has one running), and
rolls `next_run` forward. Scheduled scans are badged ⏱ in the scan list.

When a scan with a webhook finishes, the app POSTs a JSON payload describing
what's **new vs. the previous completed scan** of that target —
critical/high findings, leaked secrets, discovered hosts and newly opened
ports — so a quiet webhook means a quiet perimeter:

```json
{
  "event": "scan_complete",
  "scan_id": 8, "domain": "example.com",
  "compared_to_scan": 7,
  "new_critical_high_findings": [ {"severity": "...", "title": "...", "host": "...", "evidence": "..."} ],
  "new_secrets": [...], "new_hosts": [...], "new_open_ports": [...]
}
```

The dashboard shows upcoming schedules (interval, last run, next run).
Schedules can be paused/resumed, run immediately, or deleted via the API.

## Findings categories

- **Exposed services** — telnet/RDP/SMB/Redis/MongoDB/Docker API/etc. mapped to severities
- **Security headers** — HSTS, CSP, X-Content-Type-Options, XFO, Referrer-Policy, Permissions-Policy, COOP, CORP (scored 0–100)
- **TLS** — expired / soon-expiring certificates
- **Cookies** — missing Secure/HttpOnly/SameSite flags (session cookies escalated)
- **Exposed files** — `.git`, `.env`, `.svn`, `web.config`, `phpinfo`, `composer.json` (content-verified to avoid soft-404 false positives)
- **CORS** — wildcard and arbitrary-origin reflection (with credentials = high)
- **Secrets** — leaked API keys/tokens/private keys in client-side code (masked in storage and reports)
- **Subdomain takeover** — dangling CNAMEs to claimable third-party services (HTTP-confirmed = critical)
- **Known CVEs** — detected versions falling in vulnerable ranges
- **Email security** — SPF/DMARC/DKIM/MTA-STS weaknesses
- **Domain** — expiring / held registrations
- **Misconfigurations** — default pages, directory listings, Spring actuator, H2 console
- **Information disclosure** — server version strings, robots.txt path hints, harvested emails

## Features

- Dark dashboard with live scan progress, task updates, and a streaming log console
- Per-scan tabs: findings, live HTTP endpoints, open ports, discovered hosts + DNS records, interesting URLs, secrets, emails
- Scan diffing (⇄) between any two scans of a target
- Global findings view with severity filters
- Exports: HTML report, Markdown, CSV (findings), JSON (full) — all including secrets, emails and interesting paths
- SQLite storage (`data/imbas.db`) — everything stays local
- Bounds on every module (max IPs port-scanned, max hosts probed, max URLs stored) to keep scans polite

## Layout

```
imbas/
├── run.sh                 # start script
├── requirements.txt
├── assets/                # logo + favicon
├── data/imbas.db          # SQLite (created on first run)
└── backend/
    ├── app.py             # FastAPI app + REST API
    ├── db.py              # SQLite layer
    ├── engine/
    │   ├── orchestrator.py  # scan pipeline runner (background threads)
    │   ├── discovery.py     # subdomain enum
    │   ├── dnsmod.py        # DNS records + RDAP
    │   ├── portscan.py      # nmap wrapper + fallback
    │   ├── httpprobe.py     # HTTP/TLS probing + tech fingerprints
    │   ├── wayback.py       # Wayback CDX historical URL discovery
    │   ├── content.py       # sensitive paths, CORS, robots.txt
    │   ├── takeover.py      # subdomain takeover via dangling CNAMEs
    │   ├── cve.py           # version → known-CVE matching
    │   ├── emailsec.py      # SPF / DMARC / DKIM / MTA-STS
    │   ├── scheduler.py     # recurring scans + webhook alerts
    │   ├── secrets.py       # JS secret scanning + email harvesting
    │   ├── diffmod.py       # scan-to-scan diffing
    │   ├── analysis.py      # header scoring + findings
    │   └── report.py        # HTML/MD/CSV/JSON exports
    └── static/             # dashboard SPA (vanilla JS)
```

## API

Interactive docs at `/api/docs` (Swagger). Main endpoints:

```
GET/POST/DELETE  /api/targets
GET/POST         /api/scans          {target_id, modules[], options{}}
GET              /api/scans/{id}     live status + counts
GET              /api/scans/{id}/results
POST             /api/scans/{id}/cancel
GET              /api/scans/{id}/report?format=html|md|csv|json
GET              /api/diff?scan_a={id}&scan_b={id}
GET/POST/DELETE  /api/schedules       {target_id, interval_hours, modules[], webhook_url}
POST             /api/schedules/{id}/toggle | /run
GET              /api/dashboard
```

## Dependencies

- Python 3.10+ (FastAPI, uvicorn, httpx, dnspython)
- `nmap` and `dig` are used when available (graceful fallbacks otherwise)
