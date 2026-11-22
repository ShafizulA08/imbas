"""Scan orchestrator: runs the recon pipeline for one target as a background task."""
import asyncio
import json
import logging
import time
import traceback

import db
from engine import analysis, content, cve as cvemod, discovery, dnsmod, emailsec, httpprobe, portscan, secrets as secretsmod, takeover as takeovermod, wayback

log = logging.getLogger("imbas.orchestrator")

ALL_MODULES = ["discovery", "dns", "rdap", "ports", "http", "wayback",
               "content", "takeover", "cve", "secrets", "emailsec",
               "analysis"]

_running: set[int] = set()


class ScanJob:
    def __init__(self, scan_id: int, target_id: int, domain: str,
                 modules: list[str], options: dict,
                 webhook_url: str | None = None):
        self.scan_id = scan_id
        self.target_id = target_id
        self.domain = domain
        self.modules = modules or list(ALL_MODULES)
        self.options = options or {}
        self.webhook_url = webhook_url
        self.stats: dict = {}
        self._cancelled = False

    # -- helpers ---------------------------------------------------------

    def _update(self, **fields):
        sets = ", ".join(f"{k} = ?" for k in fields)
        db.execute(f"UPDATE scans SET {sets} WHERE id = ?",
                   (*fields.values(), self.scan_id))

    def _append_log(self, msg: str):
        stamp = time.strftime("%H:%M:%S")
        db.execute(
            "UPDATE scans SET log = COALESCE(log,'') || ? || char(10) WHERE id = ?",
            (f"[{stamp}] {msg}", self.scan_id),
        )
        log.info("scan %d: %s", self.scan_id, msg)

    def _set_progress(self, pct: float, task: str):
        self._update(progress=round(pct, 1), current_task=task)

    def check_cancelled(self) -> bool:
        row = db.query_one(
            "SELECT status FROM scans WHERE id = ?", (self.scan_id,))
        return bool(row and row["status"] == "cancelled")

    # -- pipeline --------------------------------------------------------

    async def run(self):
        self._update(status="running", started_at=time.time())
        self._append_log(f"scan started for {self.domain} "
                         f"[modules: {', '.join(self.modules)}]")
        try:
            await self._pipeline()
            if self.check_cancelled():
                self._update(status="cancelled", finished_at=time.time())
                self._append_log("scan cancelled")
            else:
                self._update(status="done", finished_at=time.time(), progress=100,
                             current_task="complete")
                self._append_log("scan complete")
        except Exception as e:
            log.exception("scan %d failed", self.scan_id)
            self._append_log(f"ERROR: {e}")
            self._append_log(traceback.format_exc()[-800:])
            self._update(status="error", finished_at=time.time(),
                         current_task=f"error: {e}")
        finally:
            _running.discard(self.scan_id)
            self._update(stats=db.j(self.stats))
            if self.webhook_url:
                try:
                    from engine import scheduler
                    scheduler.notify_webhook(self.webhook_url, self.scan_id,
                                             self.target_id, self.domain)
                except Exception:
                    log.exception("webhook notify failed for scan %d",
                                  self.scan_id)

    async def _pipeline(self):
        dom = self.domain
        hostnames: dict[str, dict] = {dom: {"ip": None, "source": "target"}}
        rdap_info: dict = {}

        # Resolve the apex so it participates in the port scan.
        import socket as _socket

        def _resolve_apex():
            try:
                for info in _socket.getaddrinfo(dom, None, _socket.AF_INET):
                    return info[4][0]
            except (_socket.gaierror, UnicodeError):
                return None

        apex_ip = await asyncio.get_running_loop().run_in_executor(
            None, _resolve_apex)
        if apex_ip:
            hostnames[dom]["ip"] = apex_ip

        # 1. RDAP domain intelligence ------------------------------------
        if "rdap" in self.modules:
            self._set_progress(5, "RDAP domain lookup")
            rdap_info = await dnsmod.rdap_domain(dom)
            if rdap_info:
                self._append_log(
                    f"RDAP: registrar={rdap_info.get('registrar') or '?'} "
                    f"expires={rdap_info.get('expires') or '?'}")
                for f in analysis.analyze_domain(rdap_info):
                    self._save_finding(f)
            else:
                self._append_log("RDAP: no data (internal/invalid domain?)")

        # 2. Subdomain discovery ------------------------------------------
        if "discovery" in self.modules:
            self._set_progress(15, "subdomain discovery")
            res = await discovery.run(
                dom,
                use_ct=self.options.get("ct", True),
                use_brute=self.options.get("brute", True),
            )
            if res["wildcard"]:
                self._append_log("DNS wildcard detected — brute results ignored")
            for h, info in res["hosts"].items():
                hostnames.setdefault(h, info)
            self.stats["subdomains"] = len(res["hosts"])
            self._append_log(f"discovered {len(res['hosts'])} resolvable subdomains")
            self._update(stats=db.j(self.stats))

        # 3. DNS records ---------------------------------------------------
        if "dns" in self.modules:
            self._set_progress(35, "DNS record enumeration")
            keys = list(hostnames.keys())
            for i, h in enumerate(keys[: self.options.get("max_dns_hosts", 60)]):
                if self.check_cancelled():
                    return
                recs = await dnsmod.records_for(h)
                if h == dom:
                    self.stats["dns_records"] = sum(len(v) for v in recs.values())
                hostnames[h]["records"] = recs
                if i % 10 == 0:
                    self._set_progress(35 + 15 * (i / max(len(keys), 1)),
                                       f"DNS records {i}/{len(keys)}")
            self._append_log(f"DNS records enumerated for "
                             f"{min(len(keys), self.options.get('max_dns_hosts', 60))} hosts")

        # persist hosts
        for h, info in hostnames.items():
            db.execute(
                "INSERT OR IGNORE INTO hosts (scan_id, hostname, ip, source, records) "
                "VALUES (?,?,?,?,?)",
                (self.scan_id, h, info.get("ip"), info.get("source", ""),
                 db.j(info.get("records", {}))),
            )
        self.stats["hosts"] = len(hostnames)
        self._update(stats=db.j(self.stats))

        # 4a. Email security (SPF/DMARC/DKIM/MTA-STS) ------------------------
        if "emailsec" in self.modules:
            self._set_progress(50, "email security (SPF/DMARC/DKIM)")
            eres = await emailsec.run(dom)
            for f in eres["findings"]:
                self._save_finding(f)
            self.stats["emailsec_findings"] = len(eres["findings"])
            self._append_log(
                f"emailsec: {len(eres['findings'])} findings "
                f"(SPF/DMARC/DKIM/MTA-STS)")
            self._update(stats=db.j(self.stats))

        # 4. Port scanning ---------------------------------------------------
        port_rows: list[dict] = []
        if "ports" in self.modules:
            ips = sorted({info["ip"] for info in hostnames.values() if info.get("ip")})
            self._set_progress(55, f"port scan ({len(ips)} unique IPs)")
            self._append_log(f"port scanning {len(ips)} IPs "
                             f"(top {self.options.get('top_ports', 100)} ports)")
            port_rows = await portscan.run(
                ips,
                top_ports=self.options.get("top_ports", 100),
                max_ips=self.options.get("max_scan_ips", 25),
            )
            for p in port_rows:
                db.execute(
                    "INSERT INTO ports (scan_id, ip, hostname, port, proto, state, "
                    "service, banner) VALUES (?,?,?,?,?,?,?,?)",
                    (self.scan_id, p["ip"], p.get("hostname"), p["port"],
                     p.get("proto", "tcp"), p.get("state", "open"),
                     p.get("service", ""), p.get("banner", "")),
                )
            self.stats["open_ports"] = len(port_rows)
            self._append_log(f"found {len(port_rows)} open ports")
            self._update(stats=db.j(self.stats))

        # 5. HTTP probing ---------------------------------------------------
        http_rows: list[dict] = []
        if "http" in self.modules:
            # web ports found by the port scan, plus defaults
            web_ports = sorted({80, 443} | {p["port"] for p in port_rows
                                            if p["port"] in httpprobe_ports()})
            self._set_progress(70, "HTTP probing")
            probe_names = list(hostnames.keys())[: self.options.get("max_http_hosts", 60)]
            self._append_log(f"HTTP probing {len(probe_names)} hostnames")
            http_rows = await httpprobe.run(probe_names, web_ports)
            for row in http_rows:
                score, _missing = analysis.score_headers(row.get("headers", {}))
                db.execute(
                    "INSERT OR IGNORE INTO http_results "
                    "(scan_id, hostname, url, status, title, server, tech, "
                    "redirect_to, tls_issuer, tls_expires, headers, header_score) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (self.scan_id, row["hostname"], row["url"], row["status"],
                     row.get("title", ""), row.get("server", ""),
                     db.j(row.get("tech", [])), row.get("redirect_to", ""),
                     row.get("tls_issuer", ""), row.get("tls_expires", ""),
                     db.j(row.get("headers", {})), score),
                )
            self.stats["live_http"] = len(http_rows)
            self._append_log(f"{len(http_rows)} live HTTP endpoints")
            self._update(stats=db.j(self.stats))

        # 6. Wayback historical URLs ----------------------------------------
        if "wayback" in self.modules and http_rows:
            self._set_progress(75, "Wayback URL history")
            live_hostnames = list(dict.fromkeys(
                r["hostname"] for r in http_rows))
            wb = await wayback.run(live_hostnames)
            interesting_urls = [u for u in wb["urls"] if u["interesting"]]
            for u in wb["urls"][: self.options.get("max_wayback_urls", 800)]:
                db.execute(
                    "INSERT OR IGNORE INTO urls (scan_id, url, source, status, "
                    "content_type, interesting, note) VALUES (?,?,?,?,?,?,?)",
                    (self.scan_id, u["url"], "wayback", u["status"],
                     u["content_type"], int(u["interesting"]), ""))
            self.stats["wayback_urls"] = len(wb["urls"])
            self.stats["wayback_interesting"] = len(interesting_urls)
            self._append_log(
                f"wayback: {len(wb['urls'])} historical URLs "
                f"({len(interesting_urls)} interesting)")
            if interesting_urls:
                self._append_log(
                    "wayback interesting paths: " + ", ".join(
                        u["url"].split("/", 3)[-1][:60]
                        for u in interesting_urls[:8]))
            self._update(stats=db.j(self.stats))
        elif "wayback" in self.modules:
            self._append_log("wayback: skipped (no live HTTP endpoints)")

        # 7. Deep content analysis --------------------------------------------
        if "content" in self.modules and http_rows:
            self._set_progress(78, "content analysis (paths/CORS/robots)")
            live_urls = [r["url"] for r in http_rows if r.get("status", 999) < 500]
            cres = await content.run(live_urls)
            for f in cres["findings"]:
                self._save_finding(f)
            for u in cres["discovered"]:
                db.execute(
                    "INSERT OR IGNORE INTO urls (scan_id, url, source, status, "
                    "content_type, interesting, note) VALUES (?,?,?,?,?,?,?)",
                    (self.scan_id, u["url"], u["source"], u["status"],
                     u["content_type"], int(u["interesting"]), u["note"]))
            self.stats["content_findings"] = len(cres["findings"])
            self._append_log(
                f"content: {len(cres['findings'])} findings across "
                f"{cres['bases']} live bases")
            self._update(stats=db.j(self.stats))
        elif "content" in self.modules:
            self._append_log("content: skipped (no live HTTP endpoints)")

        # 7a. Subdomain takeover -----------------------------------------------
        if "takeover" in self.modules:
            self._set_progress(82, "subdomain takeover check")
            tres = await takeovermod.run(hostnames)
            for f in tres["findings"]:
                self._save_finding(f)
            self.stats["takeover_candidates"] = tres["candidates"]
            self.stats["takeover_findings"] = len(tres["findings"])
            self._append_log(
                f"takeover: {tres['candidates']} third-party CNAMEs checked, "
                f"{len(tres['findings'])} findings")
            self._update(stats=db.j(self.stats))

        # 7b. Known-CVE version matching --------------------------------------
        if "cve" in self.modules and (http_rows or port_rows):
            self._set_progress(85, "known-CVE version matching")
            cvres = await asyncio.get_running_loop().run_in_executor(
                None, lambda: cvemod.run(http_rows, port_rows))
            for f in cvres["findings"]:
                self._save_finding(f)
            self.stats["cve_banners"] = cvres["banners"]
            self.stats["cve_matches"] = len(cvres["findings"])
            self._append_log(
                f"cve: {cvres['banners']} version banners checked, "
                f"{len(cvres['findings'])} known-vuln matches")
            self._update(stats=db.j(self.stats))
        elif "cve" in self.modules:
            self._append_log("cve: skipped (no banners to check)")

        # 8. Secret + email harvesting ------------------------------------------
        if "secrets" in self.modules and http_rows:
            self._set_progress(90, "JS & secret scanning")
            live_urls = [r["url"] for r in http_rows if r.get("status", 999) < 500]
            sres = await secretsmod.run(live_urls)
            for s in sres["secrets"]:
                db.execute(
                    "INSERT INTO secrets (scan_id, url, kind, value_masked, "
                    "context, created_at) VALUES (?,?,?,?,?,?)",
                    (self.scan_id, s["url"], s["kind"], s["masked"],
                     s["context"], time.time()))
                self._save_finding({
                    "severity": s["severity"],
                    "category": "secret-exposure",
                    "title": f"{s['kind']} in client-side code",
                    "host": s["url"],
                    "evidence": f"{s['masked']}  |  context: {s['context']}",
                    "recommendation": "Rotate the exposed credential immediately "
                                      "and move it server-side.",
                })
            for email, source in sres["emails"].items():
                db.execute(
                    "INSERT OR IGNORE INTO emails (scan_id, email, source) "
                    "VALUES (?,?,?)",
                    (self.scan_id, email, source))
            self.stats["secrets"] = len(sres["secrets"])
            self.stats["emails"] = len(sres["emails"])
            self.stats["js_scanned"] = sres["scripts_scanned"]
            self._append_log(
                f"secrets: {len(sres['secrets'])} secrets, "
                f"{len(sres['emails'])} emails "
                f"({sres['scripts_scanned']} scripts scanned)")
            self._update(stats=db.j(self.stats))
        elif "secrets" in self.modules:
            self._append_log("secrets: skipped (no live HTTP endpoints)")

        # 9. Analysis & findings ---------------------------------------------
        if "analysis" in self.modules:
            self._set_progress(95, "analyzing results")
            findings = analysis.analyze_ports(port_rows)
            findings += analysis.analyze_http_results([
                {**r, "headers": r.get("headers", {})} for r in http_rows
            ])
            for f in findings:
                self._save_finding(f)
            self.stats["findings"] = len(findings)
            self._append_log(f"generated {len(findings)} findings")

    def _save_finding(self, f: dict):
        db.execute(
            "INSERT INTO findings (scan_id, target_id, severity, category, title, "
            "host, evidence, recommendation, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (self.scan_id, self.target_id, f["severity"], f["category"],
             f["title"], f.get("host", ""), f.get("evidence", ""),
             f.get("recommendation", ""), time.time()),
        )


def httpprobe_ports() -> set[int]:
    from engine.portscan import WEB_PORTS
    return WEB_PORTS


def launch(scan_id: int, target_id: int, domain: str, modules: list[str],
           options: dict, webhook_url: str | None = None) -> bool:
    """Start a scan job in the background. Returns False if already running."""
    if scan_id in _running:
        return False
    _running.add(scan_id)
    job = ScanJob(scan_id, target_id, domain, modules, options,
                  webhook_url=webhook_url)

    # Dedicated thread with its own event loop for isolation.
    import threading

    def runner():
        asyncio.run(job.run())

    threading.Thread(target=runner, name=f"scan-{scan_id}", daemon=True).start()
    return True
