"""Email security posture from DNS: SPF, DMARC, DKIM, MTA-STS.

Purely passive — TXT/CNAME lookups only, plus one optional GET of the
MTA-STS policy file.
"""
import asyncio
import logging
import re

import dns.asyncresolver
import dns.exception
import httpx

log = logging.getLogger("imbas.emailsec")

resolver = dns.asyncresolver.Resolver()
resolver.lifetime = 5

# Common DKIM selectors (bounded probe).
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2",
    "k1", "k2", "dkim", "mail", "mandrill", "zoho", "protonmail",
]


async def _txt(name: str) -> list[str]:
    try:
        answers = await resolver.resolve(name, "TXT")
        return [r.to_text().strip('"') for r in answers]
    except (dns.exception.DNSException, OSError):
        return []


async def _spf_lookup_count(domain: str, spf: str, depth: int = 0) -> int:
    """Estimate SPF DNS lookups (RFC 7208 §4.6.4 limit: 10)."""
    count = 0
    for term in spf.split():
        low = term.lower()
        if low.startswith(("include:", "redirect=")):
            target = term.split(":", 1)[-1].split("=", 1)[-1]
            count += 1
            if depth < 2:  # bounded recursion
                sub = " ".join(await _txt(target))
                m = re.search(r"(?i)v=spf1\s", sub) and re.search(
                    r"(?i)(v=spf1[^\"]*)", sub)
                sub_spf = m.group(1) if m else ""
                if sub_spf:
                    count += await _spf_lookup_count(target, sub_spf, depth + 1)
        elif low.startswith(("exists:", "a:", "mx:", "mx", "a", "ptr", "ptr:")):
            if not low.startswith(("a:", "mx:", "a/", "mx/")) or ":" in low or low in ("a", "mx", "ptr"):
                count += 1
    return count


async def check_spf(domain: str) -> list[dict]:
    findings = []
    txts = await _txt(domain)
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)

    if not spf:
        findings.append({
            "severity": "medium",
            "category": "email-security",
            "title": "No SPF record",
            "host": domain,
            "evidence": f"no v=spf1 TXT record on {domain}",
            "recommendation": "Publish an SPF record (v=spf1 ... -all) listing "
                              "your mail senders.",
        })
        return findings

    # Follow redirect= chains (bounded) so the 'all' check sees the
    # effective policy (e.g. gmail.com → _spf.google.com).
    effective = spf
    seen_domains = {domain}
    for _ in range(3):
        m = re.search(r"(?i)redirect=([^\s;]+)", effective)
        if not m:
            break
        target = m.group(1).rstrip(".")
        if target in seen_domains:
            break
        seen_domains.add(target)
        sub = next((t for t in await _txt(target)
                    if t.lower().startswith("v=spf1")), "")
        if not sub:
            break
        effective = sub

    low = effective.lower()
    if "+all" in low or "?all" in low:
        findings.append({
            "severity": "high",
            "category": "email-security",
            "title": f"SPF fail-open ({'+all' if '+all' in low else '?all'})",
            "host": domain,
            "evidence": effective[:160],
            "recommendation": f"Replace {'+all' if '+all' in low else '?all'} "
                              "with -all; the current mechanism authorizes "
                              "anyone to send as this domain.",
        })
    elif "~all" in low:
        findings.append({
            "severity": "low",
            "category": "email-security",
            "title": "SPF softfail (~all)",
            "host": domain,
            "evidence": effective[:160],
            "recommendation": "Once all legitimate senders are covered, move to "
                              "-all so failures are enforced.",
        })
    elif "-all" not in low:
        findings.append({
            "severity": "medium",
            "category": "email-security",
            "title": "SPF has no 'all' mechanism",
            "host": domain,
            "evidence": effective[:160],
            "recommendation": "End the SPF record with -all (default is "
                              "neutral, which is not enforced).",
        })

    lookups = await _spf_lookup_count(domain, spf)
    if lookups > 10:
        findings.append({
            "severity": "medium",
            "category": "email-security",
            "title": f"SPF exceeds 10 DNS lookups ({lookups})",
            "host": domain,
            "evidence": spf[:160],
            "recommendation": "SPF records causing >10 DNS lookups evaluate to "
                              "PermError and are ignored — flatten includes.",
        })
    return findings


async def check_dmarc(domain: str) -> list[dict]:
    findings = []
    txts = await _txt(f"_dmarc.{domain}")
    dmarc = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)

    if not dmarc:
        findings.append({
            "severity": "medium",
            "category": "email-security",
            "title": "No DMARC record",
            "host": domain,
            "evidence": f"no v=dmarc1 TXT on _dmarc.{domain}",
            "recommendation": "Publish a DMARC policy (start p=none with "
                              "rua monitoring, then move to quarantine/reject).",
        })
        return findings

    low = dmarc.lower()
    m = re.search(r"p=(\w+)", low)
    policy = m.group(1) if m else ""
    if policy == "none":
        findings.append({
            "severity": "medium",
            "category": "email-security",
            "title": "DMARC policy is p=none (monitor only)",
            "host": domain,
            "evidence": dmarc[:160],
            "recommendation": "p=none does not affect delivery of spoofed mail "
                              "— progress to quarantine/reject.",
        })
    pct = re.search(r"pct=(\d+)", low)
    if pct and int(pct.group(1)) < 100:
        findings.append({
            "severity": "low",
            "category": "email-security",
            "title": f"DMARC applied to only {pct.group(1)}% of mail",
            "host": domain,
            "evidence": dmarc[:160],
            "recommendation": "Raise pct to 100 once tuning is complete.",
        })
    if "sp=" not in low:
        findings.append({
            "severity": "low",
            "category": "email-security",
            "title": "DMARC has no subdomain policy (sp=)",
            "host": domain,
            "evidence": dmarc[:160],
            "recommendation": "Add sp= to explicitly cover subdomains "
                              "(inherits p= otherwise).",
        })
    if "rua=" not in low:
        findings.append({
            "severity": "low",
            "category": "email-security",
            "title": "DMARC has no aggregate reports (rua=)",
            "host": domain,
            "evidence": dmarc[:160],
            "recommendation": "Add rua= to receive spoofing reports.",
        })
    return findings


async def check_dkim(domain: str) -> list[dict]:
    found = []
    probed = []

    async def probe(selector: str):
        name = f"{selector}._domainkey.{domain}"
        txts = await _txt(name)
        probed.append(selector)
        for t in txts:
            # require actual key material — empty p= (revoked/wildcard
            # placeholder records) doesn't count
            if "v=DKIM1" in t and re.search(r"p=[A-Za-z0-9+/]{20,}", t):
                found.append(selector)
                return

    await asyncio.gather(*(probe(s) for s in DKIM_SELECTORS))
    if found:
        return [{
            "severity": "info",
            "category": "email-security",
            "title": f"DKIM present (selectors: {', '.join(sorted(found))})",
            "host": domain,
            "evidence": f"DKIM TXT records found for {len(found)} of "
                        f"{len(probed)} probed selectors",
            "recommendation": "Good — ensure all senders sign with DKIM.",
        }]
    return [{
        "severity": "info",
        "category": "email-security",
        "title": "No DKIM record on common selectors",
        "host": domain,
        "evidence": f"probed: {', '.join(DKIM_SELECTORS)}",
        "recommendation": "If this domain sends mail, publish DKIM records; "
                          "note custom selector names can't be guessed.",
    }]


async def check_mta_sts(domain: str) -> list[dict]:
    txts = await _txt(f"_mta-sts.{domain}")
    if not any(t.lower().startswith("v=sts-1") for t in txts):
        return [{
            "severity": "low",
            "category": "email-security",
            "title": "No MTA-STS policy",
            "host": domain,
            "evidence": f"no v=sts-1 TXT on _mta-sts.{domain}",
            "recommendation": "Publish MTA-STS to force SMTP over TLS and "
                              "prevent downgrade/starttls stripping.",
        }]
    # Policy file check
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            r = await client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
        if r.status_code == 200 and "v=STSv1" in r.text:
            mode = re.search(r"(?i)mode:\s*(\w+)", r.text)
            if mode and mode.group(1).lower() == "testing":
                return [{
                    "severity": "info",
                    "category": "email-security",
                    "title": "MTA-STS in testing mode",
                    "host": domain,
                    "evidence": r.text[:160],
                    "recommendation": "Move to mode: enforce when ready.",
                }]
            return []
    except httpx.HTTPError:
        pass
    return [{
        "severity": "low",
        "category": "email-security",
        "title": "MTA-STS DNS record present but policy file unreachable",
        "host": domain,
        "evidence": f"https://mta-sts.{domain}/.well-known/mta-sts.txt not "
                    "serving a valid policy",
        "recommendation": "Fix the policy file — receivers will fall back to "
                          "opportunistic TLS.",
    }]


async def run(domain: str) -> dict:
    """Full email-security check for a domain."""
    results = await asyncio.gather(
        check_spf(domain), check_dmarc(domain),
        check_dkim(domain), check_mta_sts(domain),
    )
    findings = [f for group in results for f in group]
    log.info("emailsec: %d findings for %s", len(findings), domain)
    return {"findings": findings}
