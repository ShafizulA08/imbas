"""JavaScript + HTML secret scanning and email harvesting.

Fetches live pages and their scripts, then scans the text with a catalog of
provider-specific secret patterns (with false-positive suppression) and an
email regex.
"""
import asyncio
import logging
import math
import re
from urllib.parse import urljoin

import httpx

log = logging.getLogger("imbas.secrets")

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) IMBAS/1.0"}

# (kind, regex, severity, value-group index)
SECRET_PATTERNS = [
    ("Private key block",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
     "critical", 0),
    ("AWS access key ID", r"\b(AKIA[0-9A-Z]{16})\b", "critical", 1),
    ("AWS secret key",
     r"(?i)aws.{0,25}[\"']([0-9a-zA-Z/+]{40})[\"']", "high", 1),
    ("GitHub token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", "critical", 1),
    ("Google API key", r"\b(AIza[0-9A-Za-z\-_]{35})\b", "high", 1),
    ("OpenAI API key", r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b", "critical", 1),
    ("Anthropic API key", r"\b(sk-ant-[A-Za-z0-9-_]{24,})\b", "critical", 1),
    ("Slack token", r"\b(xox[baprs]-[0-9a-zA-Z-]{10,250})\b", "high", 1),
    ("Slack webhook URL",
     r"(https://hooks\.slack\.com/services/T[0-9A-Za-z]{5,}/B[0-9A-Za-z]{5,}/[0-9A-Za-z]{15,})",
     "high", 1),
    ("Stripe live key", r"\b([sk]k_live_[0-9a-zA-Z]{20,})\b", "critical", 1),
    ("Twilio API key", r"\b(SK[0-9a-f]{32})\b", "high", 1),
    ("SendGrid API key",
     r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{40,50})\b", "high", 1),
    ("Mailgun API key", r"\b(key-[0-9a-zA-Z]{32})\b", "high", 1),
    ("Postman token", r"\b(PMAK-[A-Za-z0-9-]{20,})\b", "high", 1),
    ("npm token", r"\b(npm_[A-Za-z0-9]{36})\b", "high", 1),
    ("JSON Web Token",
     r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b",
     "medium", 1),
    ("Hardcoded secret assignment",
     r"(?i)\b(api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|"
     r"auth[_-]?token|client[_-]?secret|passwd|password)\b[\"']?\s*[:=]\s*"
     r"[\"']([A-Za-z0-9_\-+/=.!$*&@#%]{12,})[\"']",
     "high", 2),
]

# Values that are certainly placeholders when they match the WHOLE value.
PLACEHOLDER_EXACT = re.compile(
    r"(?i)\A(x+|0+|[0-9]+|[a-z]+|abc123|123456|1234567890|letmein|password|"
    r"passwd|secret|token|apikey|api[-_]?key|test|sample|dummy|example|"
    r"placeholder|changeme|change-me|your[-_a-z]*|my[-_a-z]*|insert|todo|"
    r"fixme|redacted|undefined|null|none|true|false|default|value|here)\Z")

# Substrings that mark a value as a placeholder even inside longer strings.
PLACEHOLDER_SUBSTRING = re.compile(
    r"(?i)(example|placeholder|changeme|your-api|your_ |insert_|_here|todo|"
    r"fixme|sample|dummy|redact|xxxx)")

SCRIPT_SRC = re.compile(
    r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)

EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{3,}\.[A-Za-z]{2,6}\b")

EMAIL_TLDS = {
    "com", "org", "net", "edu", "gov", "io", "co", "dev", "me", "info",
    "biz", "us", "uk", "de", "fr", "nl", "eu", "ai", "app", "cloud", "xyz",
    "tech", "site", "online", "store", "shop", "ca", "au", "ch", "se", "it",
    "es", "pl", "in", "jp", "cn", "br", "mx", "ru", "be", "at", "dk", "no",
}

FAKE_EMAIL_LOCAL = re.compile(
    r"(?i)(^\.|\.$|sentry|@example\.|yours|name@|user@|email@|test@|foo@|bar@|"
    "abuse|postmaster)", )


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def scan_text(text: str) -> list[dict]:
    """Scan one text blob; returns unique secret hits."""
    hits, seen = [], set()
    for kind, pattern, severity, group in SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            value = m.group(group)
            if not value or value in seen:
                continue
            low = value.lower()
            if PLACEHOLDER_EXACT.match(value) or PLACEHOLDER_EXACT.match(low):
                continue
            if PLACEHOLDER_SUBSTRING.search(value):
                continue
            # Generic assignments need entropy or mixed-class evidence.
            if kind == "Hardcoded secret assignment":
                if _entropy(value) < 2.8 and not (
                        any(c.isdigit() for c in value)
                        and any(c.isalpha() for c in value)):
                    continue
            start = max(0, m.start() - 40)
            context = re.sub(r"\s+", " ", text[start:m.end() + 40]).strip()
            seen.add(value)
            hits.append({
                "kind": kind,
                "severity": severity,
                "value": value,
                "context": context[:160],
            })
    return hits


def extract_emails(text: str) -> list[str]:
    out = []
    for m in EMAIL.finditer(text):
        addr = m.group(0).strip(".")
        local, _, domain = addr.partition("@")
        tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        if tld not in EMAIL_TLDS:
            continue
        if FAKE_EMAIL_LOCAL.search(local) or FAKE_EMAIL_LOCAL.search(addr):
            continue
        if len(local) > 40 or re.fullmatch(r"[0-9a-f]{8,}", local):
            continue  # hash-like / tracking IDs
        out.append(addr.lower())
    return list(dict.fromkeys(out))[:40]


def mask(value: str) -> str:
    if len(value) <= 10:
        return value[:3] + "…" + value[-2:]
    return value[:8] + "…" + value[-4:]


async def _fetch(client, url: str, max_bytes: int = 300_000) -> str:
    try:
        r = await client.get(url, timeout=12)
        if r.status_code != 200 or len(r.content) > max_bytes * 4:
            return ""
        return r.text[:max_bytes]
    except httpx.HTTPError:
        return ""


async def run(live_urls: list[str], max_hosts: int = 12,
              max_scripts: int = 15) -> dict:
    """Harvest secrets + emails from live pages and their scripts."""
    bases = list(dict.fromkeys(
        u if u.count("/") <= 2 else "/".join(u.split("/")[:3])
        for u in live_urls))[:max_hosts]

    secrets: list[dict] = []
    emails: dict[str, str] = {}
    seen_secret_values: set[str] = set()
    js_scanned = 0
    sem = asyncio.Semaphore(10)

    async with httpx.AsyncClient(headers=HEADERS, follow_redirects=True,
                                 verify=True) as client:
        async def work(base_url: str):
            nonlocal js_scanned
            async with sem:
                page = await _fetch(client, base_url)
                if not page:
                    return
                texts = [("page", base_url, page)]
                for src in list(dict.fromkeys(SCRIPT_SRC.findall(page)))[:max_scripts]:
                    js_url = urljoin(base_url, src)
                    if not js_url.startswith(("http://", "https://")):
                        continue
                    js = await _fetch(client, js_url)
                    if js:
                        js_scanned += 1
                        texts.append(("script", js_url, js))
                for origin, src_url, text in texts:
                    for hit in scan_text(text):
                        if hit["value"] in seen_secret_values:
                            continue
                        seen_secret_values.add(hit["value"])
                        hit["url"] = src_url
                        hit["origin"] = origin
                        secrets.append(hit)
                    for email in extract_emails(text):
                        emails.setdefault(email, src_url)

        await asyncio.gather(*(work(b) for b in bases))

    # Mask values for storage/display.
    for s in secrets:
        s["masked"] = mask(s["value"])
        s.pop("value")

    log.info("secrets: %d found, %d emails, %d scripts scanned",
             len(secrets), len(emails), js_scanned)
    return {"secrets": secrets, "emails": emails, "scripts_scanned": js_scanned}
