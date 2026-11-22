"""HTTP probing: liveness, metadata, TLS certs, tech fingerprints."""
import asyncio
import logging
import ssl
import socket
from datetime import datetime, timezone

import httpx

log = logging.getLogger("imbas.http")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) IMBAS/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

TECH_SIGNATURES = [
    ("header", "server", r"nginx", "Nginx"),
    ("header", "server", r"Apache", "Apache"),
    ("header", "server", r"Microsoft-IIS", "Microsoft IIS"),
    ("header", "server", r"LiteSpeed", "LiteSpeed"),
    ("header", "server", r"cloudflare", "Cloudflare"),
    ("header", "server", r"awselb", "AWS ELB"),
    ("header", "server", r"gunicorn", "Gunicorn"),
    ("header", "server", r"Jetty", "Jetty"),
    ("header", "server", r"Caddy", "Caddy"),
    ("header", "x-powered-by", r"ASP\.NET", "ASP.NET"),
    ("header", "x-powered-by", r"Express", "Express"),
    ("header", "x-powered-by", r"PHP", "PHP"),
    ("header", "x-powered-by", r"Servlet", "Java Servlet"),
    ("header", "x-powered-by", r"Next\.js", "Next.js"),
    ("header", "x-generator", r"Drupal", "Drupal"),
    ("header", "x-generator", r"WordPress", "WordPress"),
    ("header", "x-drupal-cache", r".", "Drupal"),
    ("header", "x-redirect-by", r"WordPress", "WordPress"),
]


def _detect_tech(headers: dict[str, str]) -> list[str]:
    import re
    found = []
    lower = {k.lower(): v for k, v in headers.items()}
    for kind, key, pattern, name in TECH_SIGNATURES:
        value = lower.get(key, "")
        if value and re.search(pattern, value, re.I) and name not in found:
            found.append(name)
    return found


def _extract_title(body: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:200]


def _tls_info(host: str, port: int = 443, timeout: float = 6) -> dict:
    """Fetch TLS certificate issuer/expiry (blocking, run in thread)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        issuer = ""
        for rdn in cert.get("issuer", ()):  # e.g. (('organizationName','R3'),...)
            for key, value in rdn:
                if key == "organizationName":
                    issuer = value
                    break
        expires = cert.get("notAfter", "")
        return {"issuer": issuer, "expires": expires}
    except (OSError, ssl.SSLError, ValueError):
        return {"issuer": "", "expires": ""}


def _parse_expires(not_after: str) -> datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


async def probe_url(url: str, hostname: str) -> dict | None:
    """Probe one URL; returns result dict or None if unreachable."""
    try:
        async with httpx.AsyncClient(
            headers=HEADERS, follow_redirects=False, timeout=12,
            verify=True,
        ) as client:
            r = await client.get(url)
        header_map = {k.lower(): v for k, v in r.headers.items()}
        # Preserve duplicate Set-Cookie headers (collapsed by dict()).
        set_cookies = [v for k, v in r.headers.multi_items()
                       if k.lower() == "set-cookie"]
        if set_cookies:
            header_map["_cookies"] = set_cookies
        return {
            "url": url,
            "hostname": hostname,
            "status": r.status_code,
            "title": _extract_title(r.text[:20000]) if "text/html" in r.headers.get("content-type", "") else "",
            "server": header_map.get("server", ""),
            "tech": _detect_tech(r.headers),
            "redirect_to": r.headers.get("location", ""),
            "headers": dict(r.headers),
        }
    except (httpx.HTTPError, ssl.SSLError) as e:
        log.debug("probe %s failed: %s", url, e)
        return None


async def run(hostnames: list[str], web_ports: list[int] | None = None,
              max_hosts: int = 100) -> list[dict]:
    """Probe http/https for each hostname/port combination."""
    ports = web_ports or [80, 443, 8080, 8443]
    sem = asyncio.Semaphore(20)
    results: list[dict] = []

    async def work(hostname: str):
        for scheme in ("https", "http"):
            for port in ports:
                if (scheme, port) in (("http", 443), ("https", 80)):
                    continue
                url = f"{scheme}://{hostname}" if port in (80, 443) else f"{scheme}://{hostname}:{port}"
                async with sem:
                    res = await probe_url(url, hostname)
                if res:
                    # TLS details for https
                    if scheme == "https":
                        loop = asyncio.get_running_loop()
                        info = await loop.run_in_executor(
                            None, _tls_info, hostname,
                            port if port != 443 else 443,
                        )
                        res["tls_issuer"] = info["issuer"]
                        res["tls_expires"] = info["expires"]
                    results.append(res)
                    break  # first working scheme/port wins per scheme? keep going is heavy

    await asyncio.gather(*(work(h) for h in hostnames[:max_hosts]))

    # Dedupe by URL, prefer https
    by_url = {}
    for r in results:
        by_url.setdefault(r["url"], r)
    return sorted(by_url.values(), key=lambda r: (r["hostname"], r["url"]))
