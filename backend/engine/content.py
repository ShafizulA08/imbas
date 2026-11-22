"""Deep content analysis: sensitive paths, CORS, robots.txt, security.txt.

Read-only GET probes against live HTTP endpoints discovered by httpprobe.
"""
import asyncio
import json
import logging
import re

import httpx

log = logging.getLogger("imbas.content")

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) IMBAS/1.0"}

# path -> (finding title, severity, verifier(body_text, content_type))
# Verifiers prevent false positives from soft-404s and custom error pages.
CHECKS: list[tuple[str, str, str, object]] = [
    ("/.git/HEAD", "Exposed .git directory", "critical",
     lambda b, c: b.lstrip().startswith("ref: refs/")),
    ("/.git/config", "Exposed .git config", "critical",
     lambda b, c: "[core]" in b),
    ("/.env", "Exposed .env file", "critical",
     lambda b, c: len(b) < 20000 and len(re.findall(r"(?m)^[A-Z][A-Z0-9_]{2,}=", b)) >= 2),
    ("/.DS_Store", "Exposed .DS_Store file", "low",
     lambda b, c: b.startswith("\x00\x00\x00\x01Bud1")),
    ("/.svn/entries", "Exposed .svn metadata", "high",
     lambda b, c: b.strip()[:1].isdigit() or b.strip().startswith("dir")),
    ("/server-status", "Apache server-status exposed", "medium",
     lambda b, c: "Apache Server Status" in b or "Apache Status" in b),
    ("/phpinfo.php", "phpinfo() page exposed", "high",
     lambda b, c: "phpinfo()" in b or ("PHP Version" in b and "Configuration" in b)),
    ("/composer.json", "composer.json exposed", "low",
     lambda b, c: _has_keys(b, ("require", "name"))),
    ("/package.json", "package.json exposed", "info",
     lambda b, c: _has_keys(b, ("name", "dependencies", "devDependencies"))),
    ("/swagger.json", "Swagger/OpenAPI spec exposed", "medium",
     lambda b, c: _has_keys(b, ("swagger", "openapi", "paths"))),
    ("/v1/swagger.json", "Swagger/OpenAPI spec exposed", "medium",
     lambda b, c: _has_keys(b, ("swagger", "openapi", "paths"))),
    ("/api-docs", "API documentation exposed", "low",
     lambda b, c: "swagger" in b.lower() or "openapi" in b.lower()),
    ("/actuator", "Spring Boot actuator exposed", "high",
     lambda b, c: _has_keys(b, ("_links",))),
    ("/actuator/health", "Spring Boot actuator health exposed", "medium",
     lambda b, c: _has_keys(b, ("status",))),
    ("/graphql", "GraphQL endpoint exposed", "low",
     lambda b, c: "graphql" in b.lower()),
    ("/console", "H2 database console exposed", "high",
     lambda b, c: "H2 Console" in b),
    ("/web.config", "web.config file exposed", "medium",
     lambda b, c: "<?xml" in b and "configuration" in b),
    ("/crossdomain.xml", "Permissive crossdomain.xml", "low",
     lambda b, c: "allow-http-request-headers-from" in b and "*" in b),
    ("/debug/vars", "Go expvar debug endpoint exposed", "medium",
     lambda b, c: b.startswith("{")),
]

ROBOTS_DISALLOW = re.compile(r"(?im)^disallow:\s*(\S+)")


def _has_keys(body: str, keys: tuple) -> bool:
    try:
        data = json.loads(body)
        return isinstance(data, dict) and any(k in data for k in keys)
    except ValueError:
        return False


async def _get(client: httpx.AsyncClient, url: str, timeout: float = 8):
    try:
        return await client.get(url, timeout=timeout)
    except httpx.HTTPError:
        return None


async def probe_sensitive_paths(client, base_url: str) -> list[dict]:
    """Probe all sensitive paths on one base URL; returns hit dicts."""
    hits = []
    for path, title, severity, verify in CHECKS:
        r = await _get(client, base_url.rstrip("/") + path)
        if r is None or r.status_code != 200:
            continue
        body = r.text if r.encoding else r.content.decode("utf-8", "replace")
        ctype = r.headers.get("content-type", "")
        try:
            if verify(body, ctype):
                hits.append({
                    "url": base_url.rstrip("/") + path,
                    "title": title,
                    "severity": severity,
                    "evidence": f"HTTP 200, content-type: {ctype or '?'}, "
                                f"length: {len(r.content)}",
                    "recommendation": _rec_for(title),
                })
        except Exception:  # verifier blew up on odd content
            continue
    return hits


def _rec_for(title: str) -> str:
    recs = {
        ".git": "Remove the .git directory from the web root and deny access "
                "to dotfiles; rotate any credentials in its history.",
        ".env": "Remove .env from the web root, deny access, and rotate every "
                "credential it contained.",
        ".svn": "Remove SVN metadata from the web root.",
        ".DS_Store": "Remove macOS metadata files; they leak filenames.",
        "server-status": "Restrict mod_status to internal addresses.",
        "phpinfo": "Remove phpinfo.php; it discloses paths, modules and versions.",
        "composer": "Restrict access to composer.json; it discloses dependency versions.",
        "package.json": "Consider restricting package.json; it discloses dependency versions.",
        "Swagger": "Restrict API documentation to authenticated users.",
        "API documentation": "Restrict API documentation to authenticated users.",
        "actuator health": "Restrict Spring actuator endpoints to internal networks.",
        "actuator": "Restrict Spring actuator endpoints (esp. /env, /heapdump) "
                    "to internal networks; they leak credentials.",
        "GraphQL": "Consider disabling introspection in production and adding auth.",
        "H2": "The H2 console has a history of RCE; disable it in production.",
        "web.config": "Restrict access to web.config; it can leak connection strings.",
        "crossdomain": "Remove the wildcard crossdomain.xml; it enables cross-domain data theft.",
        "expvar": "Restrict /debug/vars; it leaks runtime internals.",
    }
    for k, v in recs.items():
        if k.lower() in title.lower():
            return v
    return "Restrict access to this resource."


async def check_cors(client, base_url: str, origin: str) -> dict | None:
    """Check for CORS wildcard or origin reflection (misconfiguration)."""
    r = await _get(client, base_url, timeout=8)
    if r is None:
        return None
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower()
    if not acao:
        return None
    if origin in acao:
        if acac == "true":
            return {
                "severity": "high",
                "title": "CORS reflects arbitrary origin with credentials",
                "host": base_url,
                "evidence": f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                "recommendation": "Whitelist explicit origins; never reflect "
                                  "arbitrary origins with credentials=True.",
            }
        return {
            "severity": "medium",
            "title": "CORS reflects arbitrary origin",
            "host": base_url,
            "evidence": f"Origin: {origin} → ACAO: {acao}",
            "recommendation": "Whitelist explicit origins instead of reflecting "
                              "the request Origin.",
        }
    if acao == "*":
        return {
            "severity": "low",
            "title": "CORS wildcard (Access-Control-Allow-Origin: *)",
            "host": base_url,
            "evidence": "ACAO: *",
            "recommendation": "Restrict CORS to trusted origins if the endpoint "
                              "returns sensitive data.",
        }
    return None


async def fetch_robots(client, base_url: str) -> dict:
    """Fetch + parse robots.txt for hidden path disclosure."""
    r = await _get(client, base_url.rstrip("/") + "/robots.txt")
    if r is None or r.status_code != 200:
        return {"found": False, "paths": []}
    paths = [m.group(1) for m in ROBOTS_DISALLOW.finditer(r.text)]
    # Filter trivial rules
    paths = [p for p in paths if p not in ("/", "/*", "")][:100]
    return {"found": True, "paths": paths, "body_len": len(r.text)}


async def run(live_urls: list[str], max_bases: int = 12) -> dict:
    """Run all content checks against live base URLs.

    live_urls: list of base URLs like 'https://example.com'.
    """
    findings: list[dict] = []
    discovered: list[dict] = []
    bases = list(dict.fromkeys(
        u if u.count("/") <= 2 else "/".join(u.split("/")[:3])
        for u in live_urls))[:max_bases]

    sem = asyncio.Semaphore(12)

    async with httpx.AsyncClient(headers=HEADERS, follow_redirects=False,
                                 verify=True) as client:
        cors_origin = "https://imbas-probe-external.example.net"

        async def work(base_url: str):
            async with sem:
                # 1. sensitive paths
                for hit in await probe_sensitive_paths(client, base_url):
                    hit["host"] = hit.get("host", base_url)
                    findings.append(hit)
                    discovered.append({
                        "url": hit["url"], "source": "probe",
                        "status": 200, "content_type": "",
                        "interesting": 1, "note": hit["title"],
                    })
                # 2. CORS
                cors = await check_cors(client, base_url, cors_origin)
                if cors:
                    findings.append(cors)
                # 3. robots.txt
                robots = await fetch_robots(client, base_url)
                if robots["found"]:
                    if robots["paths"]:
                        findings.append({
                            "severity": "info",
                            "category": "content",
                            "title": f"robots.txt discloses {len(robots['paths'])} paths",
                            "host": base_url,
                            "evidence": "Disallow: " + ", ".join(robots["paths"][:12])
                                        + ("…" if len(robots["paths"]) > 12 else ""),
                            "recommendation": "Review whether sensitive paths belong "
                                              "in a public robots.txt (it is a roadmap "
                                              "for attackers).",
                        })
                        for p in robots["paths"][:50]:
                            discovered.append({
                                "url": base_url.rstrip("/") + p, "source": "robots",
                                "status": 0, "content_type": "", "interesting": 0,
                                "note": "robots.txt disallow",
                            })
                    # 4. security.txt (positive signal)
                    r = await _get(client, base_url.rstrip("/") + "/.well-known/security.txt")
                    if r is not None and r.status_code == 200 and "Contact:" in r.text:
                        findings.append({
                            "severity": "info",
                            "category": "content",
                            "title": "security.txt present",
                            "host": base_url,
                            "evidence": f"{len(r.text)} bytes at /.well-known/security.txt",
                            "recommendation": "Good practice — keep it current.",
                        })

        await asyncio.gather(*(work(b) for b in bases))

    # tag category on path findings
    for f in findings:
        f.setdefault("category", "content")
    return {"findings": findings, "discovered": discovered, "bases": len(bases)}
