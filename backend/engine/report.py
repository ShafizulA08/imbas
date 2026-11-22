"""Report generation: Markdown, HTML, CSV, JSON exports."""
import json
import time

SEV_COLORS = {
    "critical": "#e5484d", "high": "#f76b15", "medium": "#f5d90a",
    "low": "#46a758", "info": "#5e6ad2",
}


def _scan_payload(conn_rows) -> dict:
    """Assemble the full result payload for a scan from DB rows."""
    scan, target = conn_rows
    return {"scan": scan, "target": target}


def build_markdown(scan: dict, target: dict, results: dict) -> str:
    lines = [
        f"# IMBAS Report — {target['domain']}",
        "",
        f"- **Scan ID:** {scan['id']}",
        f"- **Status:** {scan['status']}",
        f"- **Started:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan.get('started_at') or 0))}",
        f"- **Modules:** {', '.join(json.loads(scan['modules']))}",
        "",
        "## Summary",
        "",
    ]
    stats = json.loads(scan.get("stats") or "{}")
    for k, v in stats.items():
        lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")
    lines += ["", "## Findings", ""]
    sev_order = ["critical", "high", "medium", "low", "info"]
    for sev in sev_order:
        items = [f for f in results["findings"] if f["severity"] == sev]
        if not items:
            continue
        lines.append(f"### {sev.upper()} ({len(items)})")
        lines.append("")
        for f in items:
            lines.append(f"- **{f['title']}** — `{f['host']}`" if f["host"]
                         else f"- **{f['title']}**")
            if f["evidence"]:
                lines.append(f"  - Evidence: {f['evidence']}")
            if f["recommendation"]:
                lines.append(f"  - Fix: {f['recommendation']}")
        lines.append("")
    lines += ["## Live HTTP Endpoints", ""]
    if results["http"]:
        lines += ["| URL | Status | Title | Server | Tech | Score |",
                  "|---|---|---|---|---|---|"]
        for h in results["http"]:
            lines.append(
                f"| {h['url']} | {h['status']} | {(h['title'] or '')[:40]} | "
                f"{h['server'] or ''} | {', '.join(json.loads(h['tech'] or '[]'))} | "
                f"{h['header_score']} |")
    else:
        lines.append("_none found_")
    lines += ["", "## Open Ports", ""]
    if results["ports"]:
        lines += ["| IP | Host | Port | Service |", "|---|---|---|---|"]
        for p in results["ports"]:
            lines.append(f"| {p['ip']} | {p['hostname'] or ''} | {p['port']} | "
                         f"{p['service'] or ''} |")
    else:
        lines.append("_none found_")
    lines += ["", "## Discovered Hosts", ""]
    lines += [f"- `{h['hostname']}` → {h['ip'] or '?'} ({h['source']})"
              for h in results["hosts"]] or ["_none_"]

    if results.get("secrets"):
        lines += ["", "## Exposed Secrets", ""]
        for s in results["secrets"]:
            lines.append(f"- **{s['kind']}** — `{s['masked']}` at {s['url']}")
            if s.get("context"):
                lines.append(f"  - Context: `{s['context']}`")

    if results.get("emails"):
        lines += ["", "## Harvested Email Addresses", ""]
        lines += [f"- `{e['email']}` (source: {e['source']})"
                  for e in results["emails"]]

    interesting_urls = [u for u in (results.get("urls") or []) if u["interesting"]]
    if interesting_urls:
        lines += ["", "## Interesting Historical/Discovered Paths", ""]
        lines += [f"- `{u['url']}` ({u['source']})"
                  for u in interesting_urls[:100]]

    return "\n".join(lines)


def build_html(scan: dict, target: dict, results: dict) -> str:
    md = build_markdown(scan, target, results)
    # Tiny markdown-to-html for our own generated subset.
    import html as htmllib
    import re

    out, in_list = [], False
    for line in md.split("\n"):
        e = htmllib.escape(line)
        if e.startswith("### "):
            out.append(f"<h3>{e[4:]}</h3>")
        elif e.startswith("## "):
            out.append(f"<h2>{e[3:]}</h2>")
        elif e.startswith("# "):
            out.append(f"<h1>{e[2:]}</h1>")
        elif e.startswith("|"):
            cells = [c.strip() for c in e.strip("|").split("|")]
            tag = "th" if set(e) <= set("|-: ") else "td"
            out.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
        elif e.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{e[2:]}</li>")
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            if e:
                out.append(f"<p>{e}</p>")
    if in_list:
        out.append("</ul>")
    body = "\n".join(out)
    body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", body)
    body = re.sub(r"`(.+?)`", r"<code>\1</code>", body)
    # wrap consecutive <tr> in table
    body = re.sub(r"(<tr>.*?</tr>\n?)+",
                  lambda m: "<table>" + m.group(0) + "</table>", body, flags=re.S)

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>IMBAS Report — {htmllib.escape(target['domain'])}</title>
<style>
body{{font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;
margin:40px auto;padding:0 20px;color:#1f2328;background:#fff}}
h1,h2,h3{{line-height:1.25}} code{{background:#f4f4f5;padding:1px 5px;border-radius:4px}}
table{{border-collapse:collapse;margin:12px 0;width:100%}}
th,td{{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:13px}}
th{{background:#f6f8fa}} ul{{padding-left:22px}}
</style></head><body>{body}</body></html>"""


def build_csv(results: dict) -> str:
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "category", "title", "host", "evidence", "recommendation"])
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(results["findings"],
                    key=lambda x: sev_rank.get(x["severity"], 9)):
        w.writerow([f["severity"], f["category"], f["title"], f["host"],
                    f["evidence"], f["recommendation"]])
    return buf.getvalue()


def build_json(scan: dict, target: dict, results: dict) -> str:
    return json.dumps(
        {"target": target, "scan": {**scan, "stats": json.loads(scan["stats"] or "{}")},
         **results}, indent=2, default=str)
