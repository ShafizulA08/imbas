"""Subdomain discovery: Certificate Transparency (crt.sh) + DNS brute force."""
import asyncio
import json
import logging
import socket
import urllib.parse

import httpx

log = logging.getLogger("imbas.discovery")

# Built-in brute-force wordlist (common subdomains).
WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1",
    "smtp2", "cdn", "api", "exchange", "app", "gov", "2tty", "vps", "ovy",
    "staging", "stage", "dev", "development", "uat", "sandbox", "beta", "demo",
    "admin", "administrator", "panel", "cpanel", "whm", "webdisk", "autodiscover",
    "autoconfig", "email", "imap", "pop", "pop3", "sftp", "ssh", "git", "svn",
    "jenkins", "ci", "build", "jira", "confluence", "wiki", "docs", "status",
    "monitor", "monitoring", "grafana", "kibana", "elastic", "db", "sql",
    "mysql", "postgres", "redis", "mq", "rabbitmq", "kafka", "proxy", "gw",
    "gateway", "router", "firewall", "fw", "vpn2", "ssl", "cloud", "aws",
    "azure", "gcp", "static", "assets", "media", "images", "img", "video",
    "download", "downloads", "files", "storage", "backup", "bak", "old",
    "new", "temp", "internal", "intranet", "corp", "office", "oa", "hr",
    "crm", "erp", "support", "help", "helpdesk", "service", "services",
    "sso", "login", "auth", "id", "identity", "accounts", "account",
    "dashboard", "console", "manage", "cms", "wordpress", "wp", "drupal",
    "joomla", "shop2", "store", "ecommerce", "pay", "payment", "billing",
    "invoice", "api2", "api-dev", "api-staging", "graphql", "rest", "v1",
    "v2", "mobile", "android", "ios", "push", "notifications", "realtime",
    "ws", "wss", "socket", "chat", "forum", "community", "social", "news",
    "newsletter", "subscribe", "campaign", "marketing", "analytics", "stats",
    "tracking", "log", "logs", "syslog", "audit", "metrics", "health",
    "healthcheck", "ping", "info", "public", "private", "secret", "vault",
]

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) IMBAS/1.0"}


def _resolves(hostname: str) -> str | None:
    """Return first IPv4 for hostname, or None. Runs in a thread."""
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            return info[4][0]
    except (socket.gaierror, UnicodeError):
        pass
    return None


async def ct_search(domain: str, client: httpx.AsyncClient) -> list[str]:
    """Query crt.sh certificate transparency logs for subdomains."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    found: set[str] = set()
    try:
        r = await client.get(url, timeout=25)
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith("." + domain) and name != domain:
                        found.add(name)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
        log.info("crt.sh failed for %s: %s", domain, e)
    return sorted(found)


async def brute_force(
    domain: str, wordlist: list[str], concurrency: int = 40
) -> list[tuple[str, str]]:
    """DNS brute force; returns (hostname, ip) pairs that resolve."""
    sem = asyncio.Semaphore(concurrency)
    results: list[tuple[str, str]] = []
    loop = asyncio.get_running_loop()

    async def check(candidate: str):
        async with sem:
            ip = await loop.run_in_executor(None, _resolves, candidate)
            if ip:
                results.append((candidate, ip))

    await asyncio.gather(*(check(f"{w}.{domain}") for w in wordlist))
    return results


async def wildcard_check(domain: str) -> bool:
    """Detect DNS wildcard so brute-force results can be discounted."""
    rand = f"zzq{int(asyncio.get_event_loop().time() * 1000) % 99999}xk.{domain}"
    loop = asyncio.get_running_loop()
    ip = await loop.run_in_executor(None, _resolves, rand)
    return ip is not None


async def run(domain: str, use_ct: bool = True, use_brute: bool = True,
              extra_words: list[str] | None = None) -> dict:
    """Discover subdomains. Returns dict with hostnames -> info."""
    async with httpx.AsyncClient(headers=HEADERS, follow_redirects=True) as client:
        wildcard = await wildcard_check(domain)

        hostnames: set[str] = set()
        sources: dict[str, str] = {}

        if use_ct:
            ct_hosts = await ct_search(domain, client)
            hostnames.update(ct_hosts)
            for h in ct_hosts:
                sources[h] = "crt.sh"
            if ct_hosts:
                log.info("crt.sh: %d subdomains for %s", len(ct_hosts), domain)

        brute_pairs: list[tuple[str, str]] = []
        if use_brute:
            words = list(dict.fromkeys(WORDLIST + (extra_words or [])))
            brute_pairs = await brute_force(domain, words)
            if wildcard:
                log.info("wildcard DNS detected on %s; ignoring brute results", domain)
                brute_pairs = []
            for h, ip in brute_pairs:
                hostnames.add(h)
                sources.setdefault(h, "dns-brute")

        # Resolve any hostnames we don't have IPs for yet.
        resolved: dict[str, str] = {h: ip for h, ip in brute_pairs}
        loop = asyncio.get_running_loop()
        todo = [h for h in hostnames if h not in resolved]
        sem = asyncio.Semaphore(40)

        async def resolve(h: str):
            async with sem:
                resolved[h] = await loop.run_in_executor(None, _resolves, h)

        await asyncio.gather(*(resolve(h) for h in todo))

        return {
            "wildcard": wildcard,
            "hosts": {
                h: {"ip": resolved.get(h), "source": sources.get(h, "crt.sh")}
                for h in sorted(hostnames) if resolved.get(h)
            },
        }
