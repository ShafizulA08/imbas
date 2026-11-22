"""Port scanning: nmap wrapper with async TCP connect-scan fallback."""
import asyncio
import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET

log = logging.getLogger("imbas.ports")

RISKY_PORTS = {
    21: ("ftp", "medium"), 23: ("telnet", "high"), 69: ("tftp", "high"),
    135: ("msrpc", "medium"), 139: ("netbios-ssn", "medium"),
    445: ("microsoft-ds", "high"), 1433: ("ms-sql-s", "medium"),
    1521: ("oracle", "medium"), 2049: ("nfs", "high"),
    2375: ("docker-api", "critical"), 2376: ("docker-tls", "medium"),
    3306: ("mysql", "medium"), 3389: ("rdp", "medium"),
    5432: ("postgresql", "medium"), 5900: ("vnc", "high"),
    5984: ("couchdb", "high"), 6379: ("redis", "high"),
    9200: ("elasticsearch", "high"), 11211: ("memcached", "high"),
    27017: ("mongodb", "high"), 50000: ("upnp", "medium"),
    8080: ("http-proxy", "low"), 8443: ("https-alt", "low"),
    7001: ("weblogic", "medium"), 4848: ("glassfish", "medium"),
    61616: ("activemq", "high"),
}

WEB_PORTS = {80, 443, 591, 3000, 4443, 4567, 5000, 5601, 7000, 7070, 7777,
             8000, 8008, 8009, 8080, 8081, 8088, 8089, 8180, 8443, 8888,
             9000, 9080, 9090, 9443, 10000}


def _run_nmap(ips: list[str], top_ports: int, timeout: int) -> str:
    """Run nmap synchronously (in a thread); returns XML stdout."""
    cmd = [
        "nmap", "-Pn", "-sT", "-T4", "--open",
        "--top-ports", str(top_ports),
        "-oX", "-", "-vv",
    ] + ips
    log.info("nmap: %s", " ".join(cmd[:8]) + " ...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap XML into port rows."""
    rows = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return rows
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get("addr") if addr is not None else "?"
        hostnames = [
            h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")
        ]
        hostname = hostnames[0] if hostnames else None
        for pnode in host.findall("ports/port"):
            state = pnode.find("state")
            if state is None or state.get("state") != "open":
                continue
            port = int(pnode.get("portid"))
            service = pnode.find("service")
            rows.append({
                "ip": ip,
                "hostname": hostname,
                "port": port,
                "proto": pnode.get("protocol", "tcp"),
                "state": "open",
                "service": service.get("name", "") if service is not None else "",
                "banner": (service.get("product", "") + " " +
                           service.get("version", "")).strip()
                if service is not None else "",
            })
    return rows


async def async_connect_scan(ip: str, ports: list[int], timeout: float = 1.5,
                             concurrency: int = 200) -> list[dict]:
    """Pure-Python fallback TCP connect scan."""
    open_ports: list[dict] = []
    sem = asyncio.Semaphore(concurrency)

    async def check(port: int):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                svc, sev = RISKY_PORTS.get(port, ("", ""))
                open_ports.append({
                    "ip": ip, "hostname": None, "port": port, "proto": "tcp",
                    "state": "open", "service": svc, "banner": "",
                })
            except (OSError, asyncio.TimeoutError):
                pass

    await asyncio.gather(*(check(p) for p in ports))
    return open_ports


async def run(ips: list[str], top_ports: int = 100, max_ips: int = 25,
              timeout: int = 600) -> list[dict]:
    """Scan unique IPs. Tries nmap first, falls back to connect scan."""
    ips = list(dict.fromkeys(i for i in ips if i))[:max_ips]
    if not ips:
        return []

    if shutil.which("nmap"):
        try:
            loop = asyncio.get_running_loop()
            xml_out = await loop.run_in_executor(
                None, _run_nmap, ips, top_ports, timeout
            )
            rows = _parse_nmap_xml(xml_out)
            if rows:
                return rows
            log.info("nmap produced no rows; xml head: %s", xml_out[:200])
        except Exception as e:
            log.warning("nmap failed (%s); using connect scan", e)

    # Fallback: default top ports
    default_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 993,
        995, 1433, 1521, 2049, 2375, 3306, 3389, 4443, 5000, 5432, 5601, 5900,
        5984, 6379, 6443, 7001, 7777, 8000, 8008, 8080, 8081, 8443, 8888,
        9000, 9090, 9200, 11211, 27017,
    ][:top_ports]
    all_rows: list[dict] = []
    for ip in ips:
        all_rows.extend(await async_connect_scan(ip, default_ports))
    return all_rows
