"""DNS record enumeration + RDAP domain intelligence."""
import asyncio
import logging

import dns.asyncresolver
import httpx

log = logging.getLogger("imbas.dns")

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


async def records_for(hostname: str, types: list[str] | None = None) -> dict:
    """Fetch DNS records for a hostname. Returns {type: [values]}."""
    out: dict[str, list[str]] = {}
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5

    async def fetch(rtype: str):
        try:
            answers = await resolver.resolve(hostname, rtype)
            out[rtype] = [r.to_text().strip('"') for r in answers]
        except Exception:
            pass

    await asyncio.gather(*(fetch(t) for t in (types or RECORD_TYPES)))
    return out


async def rdap_domain(domain: str) -> dict:
    """Fetch RDAP data for a registrable domain (registrar, dates, NS)."""
    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": "IMBAS/1.0", "Accept": "application/rdap+json"},
            follow_redirects=True,
        ) as client:
            r = await client.get(f"https://rdap.org/domain/{domain}", timeout=20)
            if r.status_code != 200:
                return {}
            data = r.json()
            events = {
                e.get("eventAction"): e.get("eventDate", "")
                for e in data.get("events", [])
            }
            nameservers = sorted(
                ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])
            )
            return {
                "registrar": next(
                    (e.get("vcardArray", [None, []])[1][0][3]
                     for e in data.get("entities", [])
                     if e.get("roles") and "registrar" in e["roles"]
                     and e.get("vcardArray")), ""),
                "created": events.get("registration", ""),
                "updated": events.get("last changed", ""),
                "expires": events.get("expiration", ""),
                "nameservers": nameservers,
                "status": data.get("status", []),
            }
    except (httpx.HTTPError, ValueError, KeyError, IndexError):
        return {}
