"""IMBAS — FastAPI backend serving the dashboard API + static frontend."""
import json
import logging
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

import db  # noqa: E402
from engine import orchestrator, report, scheduler  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

app = FastAPI(title="IMBAS", docs_url="/api/docs")


# ---------------------------------------------------------------- models
class TargetIn(BaseModel):
    domain: str = Field(min_length=3)
    name: str = ""
    notes: str = ""


class ScanIn(BaseModel):
    target_id: int
    modules: list[str] = []
    options: dict = {}


class ScheduleIn(BaseModel):
    target_id: int
    interval_hours: float = Field(default=24, gt=0, le=24 * 30)
    modules: list[str] = []
    options: dict = {}
    webhook_url: str = ""


# ---------------------------------------------------------------- helpers
def _domain_valid(domain: str) -> bool:
    import re
    return bool(re.fullmatch(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", domain.lower()))


def _scan_results(scan_id: int) -> dict:
    return {
        "hosts": db.query(
            "SELECT id, hostname, ip, source, records FROM hosts "
            "WHERE scan_id = ? ORDER BY hostname", (scan_id,)),
        "ports": db.query(
            "SELECT ip, hostname, port, proto, state, service, banner FROM ports "
            "WHERE scan_id = ? ORDER BY ip, port", (scan_id,)),
        "http": db.query(
            "SELECT url, hostname, status, title, server, tech, redirect_to, "
            "tls_issuer, tls_expires, header_score FROM http_results "
            "WHERE scan_id = ? ORDER BY hostname, url", (scan_id,)),
        "urls": db.query(
            "SELECT url, source, status, content_type, interesting, note FROM urls "
            "WHERE scan_id = ? ORDER BY interesting DESC, url LIMIT 1000",
            (scan_id,)),
        "secrets": db.query(
            "SELECT url, kind, value_masked, context FROM secrets "
            "WHERE scan_id = ? ORDER BY kind, url", (scan_id,)),
        "emails": db.query(
            "SELECT email, source FROM emails WHERE scan_id = ? "
            "ORDER BY email", (scan_id,)),
        "findings": db.query(
            "SELECT id, severity, category, title, host, evidence, recommendation "
            "FROM findings WHERE scan_id = ?", (scan_id,)),
    }


def _scan_with_target(scan_id: int) -> tuple[dict, dict]:
    scan = db.query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not scan:
        raise HTTPException(404, "scan not found")
    target = db.query_one("SELECT * FROM targets WHERE id = ?",
                          (scan["target_id"],))
    return scan, target


# ---------------------------------------------------------------- targets
@app.get("/api/targets")
def list_targets():
    rows = db.query(
        "SELECT t.*, "
        "(SELECT COUNT(*) FROM scans s WHERE s.target_id = t.id) AS scan_count, "
        "(SELECT COUNT(*) FROM findings f WHERE f.target_id = t.id "
        " AND f.severity IN ('critical','high')) AS high_findings "
        "FROM targets t ORDER BY t.created_at DESC")
    for r in rows:
        r["scan_count"] = r["scan_count"] or 0
        r["high_findings"] = r["high_findings"] or 0
    return rows


@app.post("/api/targets", status_code=201)
def create_target(t: TargetIn):
    domain = t.domain.strip().lower().removeprefix("http://") \
        .removeprefix("https://").split("/")[0]
    if not _domain_valid(domain):
        raise HTTPException(422, f"'{domain}' is not a valid domain")
    if db.query_one("SELECT id FROM targets WHERE domain = ?", (domain,)):
        raise HTTPException(409, "target already exists")
    tid = db.execute(
        "INSERT INTO targets (name, domain, notes, created_at) VALUES (?,?,?,?)",
        (t.name or domain, domain, t.notes, time.time()))
    return db.query_one("SELECT * FROM targets WHERE id = ?", (tid,))


@app.delete("/api/targets/{target_id}")
def delete_target(target_id: int):
    if not db.query_one("SELECT id FROM targets WHERE id = ?", (target_id,)):
        raise HTTPException(404, "target not found")
    db.execute("DELETE FROM findings WHERE target_id = ?", (target_id,))
    db.execute("DELETE FROM scans WHERE target_id = ?", (target_id,))
    db.execute("DELETE FROM targets WHERE id = ?", (target_id,))
    return {"ok": True}


# ---------------------------------------------------------------- scans
@app.get("/api/scans")
def list_scans(target_id: int | None = None):
    if target_id:
        return db.query(
            "SELECT s.*, t.domain FROM scans s JOIN targets t ON t.id = s.target_id "
            "WHERE s.target_id = ? ORDER BY s.id DESC", (target_id,))
    return db.query(
        "SELECT s.*, t.domain FROM scans s JOIN targets t ON t.id = s.target_id "
        "ORDER BY s.id DESC")


@app.post("/api/scans", status_code=201)
def create_scan(s: ScanIn):
    target = db.query_one("SELECT * FROM targets WHERE id = ?", (s.target_id,))
    if not target:
        raise HTTPException(404, "target not found")
    modules = [m for m in (s.modules or orchestrator.ALL_MODULES)
               if m in orchestrator.ALL_MODULES]
    if not modules:
        raise HTTPException(422, "no valid modules selected")
    sid = db.execute(
        "INSERT INTO scans (target_id, status, modules, options, created_at) "
        "VALUES (?,?,?,?,?)",
        (target["id"], "queued", db.j(modules), db.j(s.options), time.time()))
    ok = orchestrator.launch(sid, target["id"], target["domain"], modules,
                             s.options)
    if not ok:
        raise HTTPException(500, "failed to launch scan")
    return {"id": sid, "status": "queued", "modules": modules}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    scan, target = _scan_with_target(scan_id)
    counts = {
        "hosts": db.query_one("SELECT COUNT(*) c FROM hosts WHERE scan_id=?",
                              (scan_id,))["c"],
        "ports": db.query_one("SELECT COUNT(*) c FROM ports WHERE scan_id=?",
                              (scan_id,))["c"],
        "http": db.query_one("SELECT COUNT(*) c FROM http_results WHERE scan_id=?",
                             (scan_id,))["c"],
        "urls": db.query_one(
            "SELECT COUNT(*) c FROM urls WHERE scan_id=? AND interesting=1",
            (scan_id,))["c"],
        "secrets": db.query_one("SELECT COUNT(*) c FROM secrets WHERE scan_id=?",
                                (scan_id,))["c"],
        "emails": db.query_one("SELECT COUNT(*) c FROM emails WHERE scan_id=?",
                               (scan_id,))["c"],
        "findings": db.query_one("SELECT COUNT(*) c FROM findings WHERE scan_id=?",
                                 (scan_id,))["c"],
    }
    sev = {r["severity"]: r["c"] for r in db.query(
        "SELECT severity, COUNT(*) c FROM findings WHERE scan_id = ? "
        "GROUP BY severity", (scan_id,))}
    return {**scan, "domain": target["domain"], "counts": counts,
            "severities": sev}


@app.get("/api/scans/{scan_id}/results")
def get_scan_results(scan_id: int):
    _scan_with_target(scan_id)
    return _scan_results(scan_id)


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int):
    _scan_with_target(scan_id)
    db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return {"ok": True}


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int):
    _scan_with_target(scan_id)
    db.execute("UPDATE scans SET status = 'cancelled', current_task = 'cancelling', "
               "finished_at = ? WHERE id = ? AND status IN ('queued','running')",
               (time.time(), scan_id))
    return {"ok": True}


@app.get("/api/scans/{scan_id}/report")
def scan_report(scan_id: int, format: str = "html"):
    scan, target = _scan_with_target(scan_id)
    results = _scan_results(scan_id)
    if format == "json":
        return JSONResponse(
            json.loads(report.build_json(scan, target, results)),
            media_type="application/json",
            headers={"Content-Disposition":
                     f'attachment; filename="imbas-{target["domain"]}.json"'})
    if format == "csv":
        return PlainTextResponse(
            report.build_csv(results), media_type="text/csv",
            headers={"Content-Disposition":
                     f'attachment; filename="imbas-{target["domain"]}-findings.csv"'})
    if format == "md":
        return PlainTextResponse(
            report.build_markdown(scan, target, results), media_type="text/markdown",
            headers={"Content-Disposition":
                     f'attachment; filename="recon-{target["domain"]}.md"'})
    return HTMLResponse(report.build_html(scan, target, results))


@app.get("/api/diff")
def diff_scans(scan_a: int, scan_b: int):
    """Diff two scans (must belong to the same target)."""
    a, ta = _scan_with_target(scan_a)
    b, tb = _scan_with_target(scan_b)
    if ta["id"] != tb["id"]:
        raise HTTPException(422, "scans belong to different targets")
    from engine import diffmod
    d = diffmod.compute_diff(a, b)
    d["a"]["domain"] = ta["domain"]
    d["b"]["domain"] = tb["domain"]
    return d


# ---------------------------------------------------------------- schedules
@app.get("/api/schedules")
def list_schedules():
    return db.query(
        "SELECT s.*, t.domain, "
        "(SELECT COUNT(*) FROM scans sc WHERE sc.target_id = s.target_id) "
        "AS scan_count FROM schedules s "
        "JOIN targets t ON t.id = s.target_id ORDER BY s.next_run ASC")


@app.post("/api/schedules", status_code=201)
def create_schedule(s: ScheduleIn):
    target = db.query_one("SELECT * FROM targets WHERE id = ?", (s.target_id,))
    if not target:
        raise HTTPException(404, "target not found")
    modules = [m for m in (s.modules or orchestrator.ALL_MODULES)
               if m in orchestrator.ALL_MODULES]
    if not modules:
        raise HTTPException(422, "no valid modules selected")
    now = time.time()
    sid = db.execute(
        "INSERT INTO schedules (target_id, interval_hours, modules, options, "
        "webhook_url, enabled, next_run, created_at) VALUES (?,?,?,?,?,1,?,?)",
        (target["id"], s.interval_hours, db.j(modules), db.j(s.options),
         s.webhook_url.strip(), now, now))
    return db.query_one("SELECT * FROM schedules WHERE id = ?", (sid,))


@app.post("/api/schedules/{schedule_id}/toggle")
def toggle_schedule(schedule_id: int):
    row = db.query_one("SELECT * FROM schedules WHERE id = ?", (schedule_id,))
    if not row:
        raise HTTPException(404, "schedule not found")
    db.execute("UPDATE schedules SET enabled = ? WHERE id = ?",
               (0 if row["enabled"] else 1, schedule_id))
    if not row["enabled"]:  # re-enabling: run soon
        db.execute("UPDATE schedules SET next_run = ? WHERE id = ?",
                   (time.time(), schedule_id))
    return db.query_one("SELECT * FROM schedules WHERE id = ?", (schedule_id,))


@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: int):
    if not db.query_one("SELECT id FROM schedules WHERE id = ?", (schedule_id,)):
        raise HTTPException(404, "schedule not found")
    db.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
    return {"ok": True}


@app.post("/api/schedules/{schedule_id}/run")
def run_schedule_now(schedule_id: int):
    row = db.query_one("SELECT * FROM schedules WHERE id = ?", (schedule_id,))
    if not row:
        raise HTTPException(404, "schedule not found")
    db.execute("UPDATE schedules SET next_run = 0, enabled = 1 WHERE id = ?",
               (schedule_id,))
    return {"ok": True, "note": "will launch within 30s"}


# ---------------------------------------------------------------- dashboard
@app.get("/api/dashboard")
def dashboard():
    return {
        "targets": db.query_one("SELECT COUNT(*) c FROM targets")["c"],
        "scans": db.query_one("SELECT COUNT(*) c FROM scans")["c"],
        "hosts": db.query_one("SELECT COUNT(*) c FROM hosts")["c"],
        "findings": db.query_one("SELECT COUNT(*) c FROM findings")["c"],
        "by_severity": {r["severity"]: r["c"] for r in db.query(
            "SELECT severity, COUNT(*) c FROM findings GROUP BY severity")},
        "recent_scans": db.query(
            "SELECT s.id, s.status, s.progress, s.started_at, s.current_task, "
            "t.domain FROM scans s JOIN targets t ON t.id = s.target_id "
            "ORDER BY s.id DESC LIMIT 8"),
        "top_findings": db.query(
            "SELECT f.severity, f.title, f.host, t.domain FROM findings f "
            "JOIN targets t ON t.id = f.target_id "
            "WHERE f.severity IN ('critical','high') "
            "ORDER BY f.created_at DESC LIMIT 8"),
        "schedules": db.query(
            "SELECT s.id, s.interval_hours, s.enabled, s.next_run, "
            "s.last_run, t.domain FROM schedules s "
            "JOIN targets t ON t.id = s.target_id "
            "WHERE s.enabled = 1 ORDER BY s.next_run ASC LIMIT 5"),
    }


# ---------------------------------------------------------------- static
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
app.mount("/assets", StaticFiles(directory=str(BASE.parent / "assets")),
          name="assets")


@app.get("/", response_class=HTMLResponse)
def index():
    return (BASE / "static" / "index.html").read_text()


db.init_db()
scheduler.start()
