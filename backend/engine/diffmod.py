"""Scan-to-scan diffing: what changed between two scans of the same target."""
import db


def _hosts(scan_id: int) -> dict[str, str]:
    return {h["hostname"]: h["ip"] or "?"
            for h in db.query("SELECT hostname, ip FROM hosts WHERE scan_id=?",
                              (scan_id,))}


def _ports(scan_id: int) -> dict[str, dict]:
    return {f"{p['ip']}:{p['port']}": p
            for p in db.query(
                "SELECT ip, port, service, hostname FROM ports WHERE scan_id=?",
                (scan_id,))}


def _http(scan_id: int) -> dict[str, dict]:
    return {r["url"]: r for r in db.query(
        "SELECT url, status, title, server FROM http_results WHERE scan_id=?",
        (scan_id,))}


def _findings(scan_id: int) -> dict[tuple, dict]:
    return {(f["severity"], f["category"], f["title"], f["host"]): f
            for f in db.query(
                "SELECT severity, category, title, host, evidence FROM findings "
                "WHERE scan_id=?", (scan_id,))}


def _secrets(scan_id: int) -> set[tuple]:
    return {(s["kind"], s["value_masked"], s["url"])
            for s in db.query(
                "SELECT kind, value_masked, url FROM secrets WHERE scan_id=?",
                (scan_id,))}


def _emails(scan_id: int) -> set[str]:
    return {e["email"] for e in db.query(
        "SELECT email FROM emails WHERE scan_id=?", (scan_id,))}


def compute_diff(scan_a: dict, scan_b: dict) -> dict:
    """Diff scan_a (older) → scan_b (newer). Returns change sets."""
    a, b = scan_a["id"], scan_b["id"]

    hosts_a, hosts_b = _hosts(a), _hosts(b)
    ports_a, ports_b = _ports(a), _ports(b)
    http_a, http_b = _http(a), _http(b)
    find_a, find_b = _findings(a), _findings(b)
    sec_a, sec_b = _secrets(a), _secrets(b)
    mail_a, mail_b = _emails(a), _emails(b)

    return {
        "a": {"id": a, "domain": scan_a.get("domain"),
              "started_at": scan_a.get("started_at")},
        "b": {"id": b, "domain": scan_b.get("domain"),
              "started_at": scan_b.get("started_at")},
        "hosts": {
            "new": [{"hostname": h, "ip": hosts_b[h]} for h in hosts_b if h not in hosts_a],
            "removed": [{"hostname": h, "ip": hosts_a[h]} for h in hosts_a if h not in hosts_b],
        },
        "ports": {
            "new": [ports_b[k] for k in ports_b if k not in ports_a],
            "removed": [ports_a[k] for k in ports_a if k not in ports_b],
        },
        "http": {
            "new": [http_b[u] for u in http_b if u not in http_a],
            "removed": [http_a[u] for u in http_a if u not in http_b],
            "changed": [
                {"url": u, "from": http_a[u]["status"], "to": http_b[u]["status"]}
                for u in http_a if u in http_b
                and http_a[u]["status"] != http_b[u]["status"]
            ],
        },
        "findings": {
            "new": [find_b[k] for k in find_b if k not in find_a],
            "resolved": [find_a[k] for k in find_a if k not in find_b],
        },
        "secrets": {
            "new": [dict(zip(("kind", "value_masked", "url"), s)) for s in sec_b - sec_a],
            "removed": [dict(zip(("kind", "value_masked", "url"), s)) for s in sec_a - sec_b],
        },
        "emails": {
            "new": sorted(mail_b - mail_a),
            "removed": sorted(mail_a - mail_b),
        },
    }
