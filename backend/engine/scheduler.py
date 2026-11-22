"""Recurring-scan scheduler + webhook notifications.

A single daemon thread wakes every 30s, launches due schedules (skipping
targets that already have an active scan), and rolls next_run forward.
Webhook delivery happens in the scan job itself when it finishes.
"""
import json
import logging
import threading
import time

import httpx

import db
from engine import orchestrator

log = logging.getLogger("imbas.scheduler")

CHECK_INTERVAL = 30
_started = False
_lock = threading.Lock()


def start():
    """Start the scheduler daemon (idempotent)."""
    global _started
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_loop, name="scheduler", daemon=True).start()
    log.info("scheduler started")


def _loop():
    while True:
        try:
            _tick()
        except Exception:
            log.exception("scheduler tick failed")
        time.sleep(CHECK_INTERVAL)


def _tick():
    now = time.time()
    due = db.query(
        "SELECT s.*, t.domain FROM schedules s "
        "JOIN targets t ON t.id = s.target_id "
        "WHERE s.enabled = 1 AND s.next_run <= ?", (now,))
    for sched in due:
        # skip if this target already has an active scan
        active = db.query_one(
            "SELECT id FROM scans WHERE target_id = ? "
            "AND status IN ('queued','running') LIMIT 1",
            (sched["target_id"],))
        if active:
            log.info("schedule %d: target %s busy (scan %d), deferring",
                     sched["id"], sched["domain"], active["id"])
            db.execute("UPDATE schedules SET next_run = ? WHERE id = ?",
                       (now + 300, sched["id"]))  # retry in 5 min
            continue

        modules = json.loads(sched["modules"] or "[]")
        options = json.loads(sched["options"] or "{}")
        options = {**options, "scheduled": True,
                   "schedule_id": sched["id"]}
        sid = db.execute(
            "INSERT INTO scans (target_id, status, modules, options, created_at) "
            "VALUES (?,?,?,?,?)",
            (sched["target_id"], "queued", db.j(modules), db.j(options),
             now))
        ok = orchestrator.launch(
            sid, sched["target_id"], sched["domain"], modules, options,
            webhook_url=sched["webhook_url"] or None)
        db.execute(
            "UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?",
            (now, now + sched["interval_hours"] * 3600, sched["id"]))
        log.info("schedule %d: launched scan %d for %s (next in %.1fh)",
                 sched["id"], sid, sched["domain"], sched["interval_hours"])


# ---------------------------------------------------------------- webhook
def notify_webhook(webhook_url: str, scan_id: int, target_id: int,
                   domain: str):
    """POST a summary of new critical/high findings vs the previous scan."""
    from engine import diffmod

    scan = db.query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not scan or scan["status"] != "done":
        return
    prev = db.query_one(
        "SELECT * FROM scans WHERE target_id = ? AND id < ? AND status = 'done' "
        "ORDER BY id DESC LIMIT 1", (target_id, scan_id))
    if prev:
        d = diffmod.compute_diff(prev, scan)
        new_findings = [f for f in d["findings"]["new"]
                        if f["severity"] in ("critical", "high")]
        payload = {
            "event": "scan_complete",
            "scan_id": scan_id,
            "target_id": target_id,
            "domain": domain,
            "finished_at": scan["finished_at"],
            "compared_to_scan": prev["id"],
            "new_critical_high_findings": [
                {"severity": f["severity"], "title": f["title"],
                 "host": f.get("host", ""), "evidence": f.get("evidence", "")}
                for f in new_findings],
            "new_secrets": [{"kind": s["kind"], "url": s["url"]}
                            for s in d["secrets"]["new"]],
            "new_hosts": [h["hostname"] for h in d["hosts"]["new"]],
            "new_open_ports": [f"{p['ip']}:{p['port']}" for p in d["ports"]["new"]],
        }
    else:
        # first scan of this target — report all crit/high findings
        rows = db.query(
            "SELECT severity, title, host, evidence FROM findings "
            "WHERE scan_id = ? AND severity IN ('critical','high') "
            "ORDER BY severity", (scan_id,))
        payload = {
            "event": "scan_complete",
            "scan_id": scan_id,
            "target_id": target_id,
            "domain": domain,
            "finished_at": scan["finished_at"],
            "compared_to_scan": None,
            "new_critical_high_findings": rows,
            "new_secrets": [], "new_hosts": [], "new_open_ports": [],
        }

    try:
        r = httpx.post(webhook_url, json=payload, timeout=10)
        log.info("webhook for scan %d → %s: %s", scan_id, webhook_url,
                 r.status_code)
    except httpx.HTTPError as e:
        log.warning("webhook for scan %d failed: %s", scan_id, e)
