"""Analysis: security header scoring + consolidated findings generation."""
import json
import re
from datetime import datetime, timezone

# Header -> (weight, recommendation)
SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS (Strict-Transport-Security)",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "on all HTTPS responses.",
    ),
    "content-security-policy": (
        "CSP (Content-Security-Policy)",
        "Define a Content-Security-Policy to mitigate XSS and injection risks.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        "Add `X-Content-Type-Options: nosniff` to prevent MIME sniffing.",
    ),
    "x-frame-options": (
        "X-Frame-Options / frame-ancestors",
        "Add `X-Frame-Options: DENY` or a CSP `frame-ancestors` directive "
        "to prevent clickjacking.",
    ),
    "referrer-policy": (
        "Referrer-Policy",
        "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
    "permissions-policy": (
        "Permissions-Policy",
        "Add a Permissions-Policy to restrict camera, microphone, geolocation.",
    ),
    "cross-origin-opener-policy": (
        "COOP (Cross-Origin-Opener-Policy)",
        "Add `Cross-Origin-Opener-Policy: same-origin`.",
    ),
    "cross-origin-resource-policy": (
        "CORP (Cross-Origin-Resource-Policy)",
        "Add `Cross-Origin-Resource-Policy: same-origin`.",
    ),
}

RISKY_PORT_FINDINGS = {
    23: ("Telnet exposed", "high",
         "Telnet transmits credentials in cleartext. Disable it and use SSH."),
    21: ("FTP exposed", "medium",
         "FTP transmits credentials in cleartext. Replace with SFTP/FTPS."),
    445: ("SMB exposed to the internet", "high",
           "SMB should never face the internet (EternalBlue-class risk). "
           "Restrict to VPN/internal access."),
    3389: ("RDP exposed", "high",
           "RDP exposed to the internet is a common ransomware entry point. "
           "Restrict to VPN/internal access."),
    6379: ("Redis exposed", "high",
           "Unauthenticated Redis instances allow arbitrary file writes. "
           "Bind to localhost and enable AUTH."),
    27017: ("MongoDB exposed", "high",
            "Open MongoDB instances frequently leak data. "
            "Enable auth and bind to localhost."),
    9200: ("Elasticsearch exposed", "high",
           "Open Elasticsearch commonly exposes indexed data. "
           "Enable TLS+auth or restrict network access."),
    5900: ("VNC exposed", "high",
           "VNC exposed externally often lacks encryption. "
           "Restrict to VPN/internal access."),
    2375: ("Docker API exposed without TLS", "critical",
           "The unauthenticated Docker API grants instant host takeover "
           "(read/write host filesystem, spawn privileged containers). "
           "Disable the TCP endpoint or enforce TLS+auth."),
    11211: ("Memcached exposed", "high",
             "Open memcached enables reflection DDoS and may leak session data."),
    2049: ("NFS exposed", "high",
           "NFS on the internet usually means exported filesystems to anyone."),
}

SEVERITY_WEIGHT = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 90}


def score_headers(response_headers: dict) -> tuple[float, list[str]]:
    """Return (0-100 score, missing header keys)."""
    lower = {k.lower(): v for k, v in response_headers.items()}
    missing = [k for k in SECURITY_HEADERS if k not in lower]
    present = len(SECURITY_HEADERS) - len(missing)
    score = round(100 * present / len(SECURITY_HEADERS), 1)
    return score, missing


def analyze_http_results(http_rows: list[dict]) -> list[dict]:
    """Generate findings from HTTP probe results (already scored/stored)."""
    findings: list[dict] = []
    for row in http_rows:
        headers = row.get("headers") or {}
        if isinstance(headers, str):
            headers = json.loads(headers or "{}")
        score, missing = score_headers(headers)

        # Missing security headers on HTML endpoints
        if score < 100 and (row.get("status") or 0) < 400:
            findings.append({
                "severity": "low" if score >= 50 else "medium",
                "category": "security-headers",
                "title": f"Missing {len(missing)} security headers ({score}/100)",
                "host": row["url"],
                "evidence": "Missing: " + ", ".join(
                    SECURITY_HEADERS[m][0] for m in missing),
                "recommendation": " ".join(
                    SECURITY_HEADERS[m][1] for m in missing[:3]),
            })

        # Cookie security flags
        for cookie in headers.get("_cookies", []):
            name = cookie.split("=", 1)[0].strip()
            if not name:
                continue
            flags = cookie.lower()
            missing = []
            if "httponly" not in flags:
                missing.append("HttpOnly")
            if "secure" not in flags:
                missing.append("Secure")
            if "samesite" not in flags:
                missing.append("SameSite")
            if not missing:
                continue
            sessionish = bool(re.search(
                r"(sess|session|auth|token|jwt|sid|login|remember)",
                name, re.I))
            findings.append({
                "severity": "medium" if (sessionish and "secure" in
                                         [m.lower() for m in missing])
                            else "low",
                "category": "cookies",
                "title": f"Cookie '{name}' missing {', '.join(missing)}",
                "host": row["url"],
                "evidence": cookie[:160],
                "recommendation": "Set Secure, HttpOnly and SameSite flags "
                                  "on session cookies.",
            })

        # TLS expiry
        if row.get("tls_expires"):
            exp = _parse_dt(row["tls_expires"])
            if exp:
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    findings.append({
                        "severity": "high",
                        "category": "tls",
                        "title": f"TLS certificate expired {-days} days ago",
                        "host": row["url"],
                        "evidence": f"notAfter={row['tls_expires']}",
                        "recommendation": "Renew the TLS certificate immediately.",
                    })
                elif days < 21:
                    findings.append({
                        "severity": "low",
                        "category": "tls",
                        "title": f"TLS certificate expires in {days} days",
                        "host": row["url"],
                        "evidence": f"notAfter={row['tls_expires']}",
                        "recommendation": "Schedule certificate renewal.",
                    })

        # Server version disclosure
        server = (row.get("server") or "")
        if any(c.isdigit() for c in server):
            findings.append({
                "severity": "info",
                "category": "information-disclosure",
                "title": f"Server version disclosed: {server}",
                "host": row["url"],
                "evidence": f"Server: {server}",
                "recommendation": "Strip version numbers from the Server header.",
            })

        # Directory-listing-ish or default pages
        title = (row.get("title") or "").lower()
        if title in ("index of /", "apache2 ubuntu default page",
                     "welcome to nginx!", "iis windows server"):
            findings.append({
                "severity": "medium",
                "category": "misconfiguration",
                "title": f"Default/listing page exposed: {row.get('title')}",
                "host": row["url"],
                "evidence": f"<title>{row.get('title')}</title>",
                "recommendation": "Replace the default page; disable directory "
                                  "listing (Options -Indexes).",
            })

    return findings


def analyze_ports(port_rows: list[dict]) -> list[dict]:
    findings = []
    seen: set[tuple] = set()
    for p in port_rows:
        key = (p["ip"], p["port"])
        if key in seen:
            continue
        seen.add(key)
        if p["port"] in RISKY_PORT_FINDINGS:
            name, sev, rec = RISKY_PORT_FINDINGS[p["port"]]
            findings.append({
                "severity": sev,
                "category": "exposed-service",
                "title": f"{name} on {p['ip']}:{p['port']}",
                "host": f"{p['ip']}:{p['port']}",
                "evidence": f"TCP port {p['port']} open "
                            f"(service: {p.get('service') or 'unknown'})",
                "recommendation": rec,
            })
    return findings


def analyze_domain(rdap: dict) -> list[dict]:
    findings = []
    if rdap.get("expires"):
        exp = _parse_dt(rdap["expires"])
        if exp:
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append({
                    "severity": "medium", "category": "domain",
                    "title": f"Domain expired {-days} days ago",
                    "host": "", "evidence": rdap["expires"],
                    "recommendation": "Renew the domain registration.",
                })
            elif days < 30:
                findings.append({
                    "severity": "low", "category": "domain",
                    "title": f"Domain expires in {days} days",
                    "host": "", "evidence": rdap["expires"],
                    "recommendation": "Schedule domain renewal.",
                })
    if rdap.get("status") and any("clientHold" in s or "serverHold" in s
                                  for s in rdap["status"]):
        findings.append({
            "severity": "medium", "category": "domain",
            "title": "Domain is on hold status",
            "host": "", "evidence": ", ".join(rdap["status"]),
            "recommendation": "Resolve the registry hold.",
        })
    return findings


def _parse_dt(value: str) -> datetime | None:
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%b %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None
