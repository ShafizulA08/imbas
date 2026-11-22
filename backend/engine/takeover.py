"""Subdomain takeover detection via dangling CNAME records.

Fingerprints third-party services that return a recognizable "not found"
response when the referenced account/bucket/site has been deleted. A match
means the hostname can likely be claimed by registering the service name.
"""
import asyncio
import logging

import httpx

log = logging.getLogger("imbas.takeover")

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) IMBAS/1.0"}

# (cname suffix, service name, evidence substring in response body, status)
SERVICES: list[tuple[str, str, str, int]] = [
    ("herokuapp.com", "Heroku", "no such app", 404),
    ("github.io", "GitHub Pages",
     "there isn't a github pages site here", 404),
    ("azurewebsites.net", "Azure App Service",
     "404 web site not found", 404),
    ("azure-api.net", "Azure API Management", "not found", 404),
    ("cloudapp.net", "Azure Cloud App", "not found", 404),
    ("trafficmanager.net", "Azure Traffic Manager", "not found", 404),
    ("azureedge.net", "Azure CDN", "not found", 404),
    ("blob.core.windows.net", "Azure Blob Storage",
     "the specified resource does not exist", 404),
    ("cloudfront.net", "AWS CloudFront",
     "bad request", 400),
    ("awselasticbeanstalk.com", "AWS Elastic Beanstalk", "nx-domain", 404),
    ("s3.amazonaws.com", "AWS S3", "nosuchbucket", 404),
    ("storage.googleapis.com", "Google Cloud Storage",
     "the specified bucket does not exist", 404),
    ("pantheon.io", "Pantheon", "the gods are wise", 404),
    ("surge.sh", "Surge.sh", "project not found", 404),
    ("bitbucket.io", "Bitbucket Cloud", "repository not found", 404),
    ("readme.io", "ReadMe", "project not found", 404),
    ("netlify.app", "Netlify", "not found", 404),
    ("vercel.app", "Vercel", "deployment_not_found", 404),
    ("ngrok.io", "ngrok", "tunnel", 404),
    ("zendesk.com", "Zendesk", "help center closed", 404),
    ("shopify.com", "Shopify", "sorry, this shop is currently unavailable", 404),
    ("wordpress.com", "WordPress.com", "do you want to register", 404),
]

MAX_HOSTS = 30


def match_service(cname: str) -> tuple[str, str, int] | None:
    """Return (service, evidence, status) if the CNAME matches a fingerprint."""
    c = cname.rstrip(".").lower()
    for suffix, service, evidence, status in SERVICES:
        if c == suffix or c.endswith("." + suffix):
            return service, evidence, status
    return None


async def _fetch(client, url: str) -> tuple[int, str]:
    try:
        r = await client.get(url, timeout=10)
        return r.status_code, r.text[:20000].lower()
    except httpx.HTTPError:
        return 0, ""


async def run(hostnames: dict[str, dict]) -> dict:
    """Check hostnames (with their DNS records) for takeover potential.

    hostnames: {hostname: {"records": {"CNAME": [...]}, ...}} — orchestrator shape.
    """
    findings: list[dict] = []
    checked = 0

    candidates: list[tuple[str, str, str, int]] = []  # host, cname, service, status
    for host, info in hostnames.items():
        cnames = (info.get("records") or {}).get("CNAME") or []
        if not cnames:
            continue
        for cname in cnames:
            m = match_service(cname)
            if m:
                service, _evidence, status = m
                candidates.append((host, cname, service, status))
                break

    sem = asyncio.Semaphore(8)

    async with httpx.AsyncClient(headers=HEADERS, follow_redirects=True,
                                 verify=True) as client:

        async def check(host: str, cname: str, service: str, want_status: int):
            nonlocal checked
            async with sem:
                # try https then http
                for url in (f"https://{host}", f"http://{host}"):
                    status, body = await _fetch(client, url)
                    if status:
                        checked += 1
                        evidence_url = url
                        break
                else:
                    return

                service_match = None
                for suffix, svc, evidence, st in SERVICES:
                    if svc == service:
                        service_match = (suffix, evidence, st)
                suffix, evidence, _st = service_match

                if status == want_status and evidence in body:
                    findings.append({
                        "severity": "critical",
                        "category": "takeover",
                        "title": f"Subdomain takeover: {host} ({service})",
                        "host": host,
                        "evidence": f"CNAME → {cname}; {evidence_url} returns "
                                    f"{status} with '{service}' not-found page",
                        "recommendation": f"Remove the dangling CNAME, or reclaim "
                                          f"the {service} resource before an "
                                          f"attacker does.",
                    })
                elif status in (400, 404, 410, 502):
                    findings.append({
                        "severity": "high",
                        "category": "takeover",
                        "title": f"Dangling CNAME to {service}: {host}",
                        "host": host,
                        "evidence": f"CNAME → {cname}; {evidence_url} returns "
                                    f"{status}",
                        "recommendation": f"Verify whether the {service} resource "
                                          f"can be claimed; remove the CNAME if "
                                          f"obsolete.",
                    })
                else:
                    findings.append({
                        "severity": "info",
                        "category": "takeover",
                        "title": f"CNAME to third-party service: {host} → {service}",
                        "host": host,
                        "evidence": f"CNAME → {cname}; responds {status}",
                        "recommendation": "Third-party CNAME — monitor for "
                                          "decommissioning.",
                    })

        await asyncio.gather(*(check(*c) for c in candidates[:MAX_HOSTS]))

    log.info("takeover: %d candidates checked, %d findings",
             min(len(candidates), MAX_HOSTS), len(findings))
    return {"findings": findings, "candidates": len(candidates),
            "checked": checked}
