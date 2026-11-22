"""Wayback Machine historical URL discovery via the CDX API."""
import logging
import re
from urllib.parse import urlparse

import httpx

log = logging.getLogger("imbas.wayback")

CDX_API = "https://web.archive.org/cdx/search/cdx"

# Paths that hint at sensitive or interesting historical content.
INTERESTING = re.compile(
    r"(\.env|\.git|\.svn|\.hg|\.bak|\.old|\.sql|\.dump|backup|restore|admin|"
    r"config|secret|token|credential|passwd|password|\.pem|\.key|id_rsa|"
    r"\.keystore|\.aws|phpunit|composer\.json|wp-config|debug|swagger|"
    r"api-doc|graphql|\.DS_Store|\.zip$|\.tar|\.gz$|/tmp/|upload|export|"
    r"internal|staging|test|sandbox|\.csv|\.xlsx|dump\.|db\.)", re.I)

# Static assets we never care about.
SKIP_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|css|less|scss|woff2?|ttf|eot|otf|mp4|webm|"
    r"webp|avif|mp3|wav|pdf|woff)(\?|$)", re.I)


async def fetch_urls(hostname: str, limit: int = 1500) -> list[dict]:
    """Fetch historical 200-OK URLs for a hostname from the Wayback CDX API."""
    params = {
        "url": f"{hostname}/*",
        "output": "json",
        "collapse": "urlkey",
        "fl": "original,statuscode,mimetype",
        "filter": "statuscode:200",
        "limit": str(limit),
    }
    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": "IMBAS/1.0"}, timeout=35, follow_redirects=True
        ) as client:
            r = await client.get(CDX_API, params=params)
            if r.status_code != 200:
                log.info("wayback: CDX returned %d for %s", r.status_code, hostname)
                return []
            rows = r.json()
    except (httpx.HTTPError, ValueError) as e:
        log.info("wayback failed for %s: %s", hostname, e)
        return []

    out: list[dict] = []
    seen: set[str] = set()
    for row in rows[1:]:  # first row is the header
        try:
            original, status, mime = row[0], row[1], row[2]
        except (IndexError, TypeError):
            continue
        url = str(original)
        if url in seen or not url.startswith("http"):
            continue
        seen.add(url)
        path = urlparse(url).path
        if SKIP_EXT.search(path):
            continue
        out.append({
            "url": url,
            "status": int(status) if str(status).isdigit() else 0,
            "content_type": str(mime or ""),
            "interesting": bool(INTERESTING.search(path)),
        })
    return out


async def run(hostnames: list[str], per_host_limit: int = 1500,
              max_hosts: int = 6) -> dict:
    """Fetch wayback history for the given hostnames, merged + deduped."""
    merged: dict[str, dict] = {}
    per_host_counts: dict[str, int] = {}
    for hostname in hostnames[:max_hosts]:
        urls = await fetch_urls(hostname, per_host_limit)
        per_host_counts[hostname] = len(urls)
        for u in urls:
            merged.setdefault(u["url"], u)
    interesting = [u for u in merged.values() if u["interesting"]]
    log.info("wayback: %d total URLs, %d interesting",
             len(merged), len(interesting))
    return {
        "urls": sorted(merged.values(), key=lambda u: (not u["interesting"], u["url"])),
        "interesting": len(interesting),
        "per_host": per_host_counts,
    }
