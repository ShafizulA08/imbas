"""Known-vulnerability matching: detected versions → high-profile CVEs.

Offline catalog only (no external API). Version evidence comes from HTTP
server/x-powered-by headers, tech fingerprints, and port service banners.
Ranges are inclusive. Version tuples handle OpenSSH-style 'p1' patch
suffixes (ignored for ordering) and OpenSSL-style letter suffixes
('1.0.1f' < '1.0.1g').
"""
import logging
import re

log = logging.getLogger("imbas.cve")


def vtuple(version: str) -> tuple:
    """'2.4.50' → (2,4,50); '8.9p1' → (8,9,0); '1.0.1f' → (1,0,1,102)."""
    tokens = re.findall(r"\d+|[a-z]+", version.lower())
    parts: list[int] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.isdigit():
            parts.append(int(tok))
        else:
            # 'p1'-style patch suffix (letter followed by digit): neutral,
            # so '9.7p1' compares equal to '9.7'.
            if i + 1 < len(tokens) and tokens[i + 1].isdigit():
                parts.append(0)
                i += 1
            else:
                # bare letter (OpenSSL 1.0.1f) → ordinal for fine ordering
                parts.append(ord(tok[0]))
        i += 1
    return tuple(parts or (0,))


def in_range(version: str, lo: str, hi: str) -> bool:
    v, lo_v, hi_v = vtuple(version), vtuple(lo), vtuple(hi)
    width = max(len(v), len(lo_v), len(hi_v))

    def pad(t):
        return t + (0,) * (width - len(t))

    v, lo_v, hi_v = pad(v), pad(lo_v), pad(hi_v)
    return lo_v <= v <= hi_v


# (product regex on banner, version regex (group 1), lo, hi, cve, severity, summary)
CATALOG = [
    (r"(?i)apache[/\s]", r"(\d+\.\d+(?:\.\d+)?)",
     "2.4.49", "2.4.50", "CVE-2021-41773 / CVE-2021-42013", "critical",
     "Apache path traversal + RCE when CGI is enabled"),
    (r"(?i)apache[/\s]", r"(\d+\.\d+(?:\.\d+)?)",
     "2.4.0", "2.4.48", "CVE-2021-41773", "high",
     "Apache ≤2.4.48 path traversal (fixed in 2.4.49 — see also 42013)"),
    (r"(?i)openssh", r"openssh_?(\d+\.\d+(?:\.\d+)?(?:p\d+)?)",
     "8.5", "9.7", "CVE-2024-6387 (regreSSHion)", "high",
     "OpenSSH signal-handler race → unauthenticated RCE as root"),
    (r"(?i)openssh", r"openssh_?(\d+\.\d+(?:\.\d+)?(?:p\d+)?)",
     "5.4", "9.3", "CVE-2023-38408", "medium",
     "OpenSSH ssh-agent RCE via forwarded agent socket"),
    (r"(?i)nginx/", r"nginx/(\d+\.\d+(?:\.\d+)?)",
     "1.1.4", "1.2.0", "CVE-2012-1182", "medium",
     "nginx stack buffer overflow in chunked transfer encoding"),
    (r"(?i)nginx/", r"nginx/(\d+\.\d+(?:\.\d+)?)",
     "0.5.6", "1.13.2", "CVE-2017-7529", "low",
     "nginx integer overflow → sensitive info leak (mp4 module)"),
    (r"(?i)jenkins", r"(\d+\.\d+(?:\.\d+)?)",
     "1.0", "2.441", "CVE-2024-23897", "critical",
     "Jenkins arbitrary file read → RCE via CLI (any logged-in user)"),
    (r"(?i)exim", r"(\d+\.\d+(?:\.\d+)?)",
     "4.87", "4.91", "CVE-2019-10149", "critical",
     "Exim RCE via crafted recipient address"),
    (r"(?i)vsftpd", r"(\d+\.\d+(?:\.\d+)?)",
     "2.3.4", "2.3.4", "CVE-2011-2523", "critical",
     "vsftpd 2.3.4 backdoor — malicious version, root shell on 6200/tcp"),
    (r"(?i)proftpd", r"(\d+\.\d+(?:\.\d+)?)",
     "1.3.5", "1.3.5", "CVE-2015-3306", "critical",
     "ProFTPD mod_copy RCE"),
    (r"(?i)tomcat", r"(\d+\.\d+(?:\.\d+)?)",
     "7.0.0", "9.0.17", "CVE-2020-1938 (Ghostcat)", "high",
     "Tomcat AJP Ghostcat file read/include (check 8009/tcp exposure)"),
    (r"(?i)tomcat", r"(\d+\.\d+(?:\.\d+)?)",
     "7.0.0", "7.0.79", "CVE-2017-12617", "critical",
     "Tomcat PUT RCE when DefaultServlet is writable"),
    (r"(?i)openssl/", r"openssl/(\d+\.\d+(?:\.\d+)?[a-z]?)",
     "1.0.1", "1.0.1f", "CVE-2014-0160 (Heartbleed)", "critical",
     "OpenSSL Heartbleed — leaks server memory incl. private keys"),
    (r"(?i)openssl/", r"openssl/(\d+\.\d+(?:\.\d+)?[a-z]?)",
     "1.0.1", "1.0.1g", "CVE-2014-0224", "high",
     "OpenSSL ChangeCipherSpec mid-handshake DoS"),
    (r"(?i)\biis/", r"iis/(\d+\.\d+)",
     "6.0", "6.0", "CVE-2017-7269", "high",
     "IIS 6.0 WebDAV buffer overflow → RCE"),
    (r"(?i)struts", r"(\d+\.\d+(?:\.\d+)?)",
     "2.3.0", "2.5.10", "CVE-2017-5638", "critical",
     "Apache Struts2 RCE via Content-Type header (Equifax breach)"),
    (r"(?i)drupal", r"(\d+\.\d+(?:\.\d+)?)",
     "8.0.0", "8.5.1", "CVE-2018-7600 (Drupalgeddon 2)", "critical",
     "Drupal remote code execution"),
    (r"(?i)drupal", r"(\d+\.\d+(?:\.\d+)?)",
     "7.0", "7.57", "CVE-2018-7600 (Drupalgeddon 2)", "critical",
     "Drupal 7.x remote code execution"),
    (r"(?i)php/", r"php/(\d+\.\d+(?:\.\d+)?)",
     "5.0.0", "5.6.99", "PHP 5.x EOL", "low",
     "PHP 5.x is end-of-life (no security patches since Jan 2019)"),
    (r"(?i)php/", r"php/(\d+\.\d+(?:\.\d+)?)",
     "7.0.0", "7.4.33", "PHP 7.x EOL", "low",
     "PHP 7.x is end-of-life (no security patches since Nov 2022)"),
    (r"(?i)\bredis", r"(\d+\.\d+(?:\.\d+)?)",
     "2.0.0", "6.2.5", "CVE-2022-0543", "high",
     "Redis Lua sandbox escape (Debian-packaged Redis) → RCE"),
]


def scan_banners(banners: list[tuple[str, str]]) -> list[dict]:
    """Scan (source, banner) pairs against the catalog. Returns findings."""
    findings: list[dict] = []
    seen: set[tuple] = set()

    for source, banner in banners:
        if not banner:
            continue
        for prod_re, ver_re, lo, hi, cve, severity, summary in CATALOG:
            if not re.search(prod_re, banner):
                continue
            vm = re.search(ver_re, banner, re.I)
            if not vm:
                continue
            version = vm.group(1)
            if not in_range(version, lo, hi):
                continue
            key = (cve, version, source)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "severity": severity,
                "category": "known-cve",
                "title": f"{cve} — {summary}",
                "host": source,
                "evidence": f"detected version {version} (vulnerable range "
                            f"{lo}–{hi}) in: {banner[:120]}",
                "recommendation": f"Upgrade to a fixed version — see {cve} "
                                  "advisory for patches.",
            })
    return findings


def collect_banners(http_rows: list[dict], port_rows: list[dict]) -> list[tuple]:
    """Gather (source, banner) pairs from all version-bearing evidence."""
    out: list[tuple[str, str]] = []
    for r in http_rows:
        headers = r.get("headers", {}) or {}
        lower = {k.lower(): v for k, v in headers.items()}
        for h in ("server", "x-powered-by", "x-jenkins", "x-generator",
                  "x-aspnet-version", "x-runtime"):
            v = lower.get(h)
            if v:
                out.append((r["url"], f"{h}:{v}"))
        for t in r.get("tech", []) or []:
            out.append((r["url"], str(t)))
        if r.get("server"):
            out.append((r["url"], r["server"]))
    for p in port_rows:
        if p.get("banner"):
            out.append((f"{p['ip']}:{p['port']}", p["banner"]))
    return out


def run(http_rows: list[dict], port_rows: list[dict]) -> dict:
    banners = collect_banners(http_rows, port_rows)
    findings = scan_banners(banners)
    log.info("cve: %d banners checked, %d matches", len(banners), len(findings))
    return {"findings": findings, "banners": len(banners)}
