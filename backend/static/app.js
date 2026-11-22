/* IMBAS frontend */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

const state = {
  view: "dashboard",
  scanId: null,
  scanTab: "findings",
  findingFilter: "all",
  pollTimer: null,
  scanTargets: null, // target for the new-scan modal
};

const MODULES = [
  ["discovery", "Subdomain discovery (crt.sh + DNS brute)"],
  ["dns", "DNS records (A/MX/NS/TXT…)"],
  ["rdap", "RDAP domain intelligence"],
  ["emailsec", "Email security: SPF / DMARC / DKIM / MTA-STS"],
  ["ports", "Port scan (nmap)"],
  ["http", "HTTP/TLS probing"],
  ["wayback", "Wayback Machine URL history + interesting paths"],
  ["content", "Sensitive paths, CORS, robots.txt, cookies"],
  ["takeover", "Subdomain takeover (dangling CNAMEs)"],
  ["cve", "Known-CVE matching on detected versions"],
  ["secrets", "JavaScript & secret scanning + emails"],
  ["analysis", "Findings & scoring"],
];

const api = async (path, opts = {}) => {
  const r = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" }, ...opts,
  });
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  return r.json();
};

function toast(msg, error = false) {
  const el = document.createElement("div");
  el.className = `toast${error ? " error" : ""}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleString() : "—";

function sevBadge(sev) { return `<span class="badge ${esc(sev)}">${esc(sev)}</span>`; }
function statusBadge(s) { return `<span class="badge ${esc(s)}">${esc(s)}</span>`; }

/* ================= navigation ================= */
$("#nav").addEventListener("click", (e) => {
  const btn = e.target.closest(".nav-item");
  if (!btn) return;
  go(btn.dataset.view);
});

function go(view, scanId = null) {
  state.view = view;
  state.scanId = scanId;
  $$(".nav-item").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === view || (view === "scan" && b.dataset.view === "scans")));
  $("#view-title").textContent =
    view === "scan" ? `Scan #${scanId}` :
    view[0].toUpperCase() + view.slice(1);
  stopPolling();
  render();
}

function stopPolling() {
  if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
}

/* ================= render dispatch ================= */
async function render() {
  const v = $("#view");
  if (state.view === "dashboard") return renderDashboard(v);
  if (state.view === "targets") return renderTargets(v);
  if (state.view === "scans") return renderScans(v);
  if (state.view === "findings") return renderFindings(v);
  if (state.view === "scan") return renderScanDetail(v, state.scanId);
}

/* ================= dashboard ================= */
async function renderDashboard(v) {
  const d = await api("/dashboard");
  const sev = d.by_severity || {};
  $("#topbar-actions").innerHTML =
    `<button class="btn primary" id="btn-add">+ Add target</button>`;
  $("#btn-add").onclick = openTargetModal;

  const recentRows = (d.recent_scans || []).map((s) => `
    <tr class="clickable" onclick="go('scan', ${s.id})">
      <td class="mono">${esc(s.domain)}</td>
      <td>${statusBadge(s.status)}</td>
      <td><div class="progress-row">
        <div class="progress-track"><div class="progress-fill" style="width:${s.progress || 0}%"></div></div>
        <span class="progress-pct">${Math.round(s.progress || 0)}%</span></div></td>
      <td class="dim">${esc(s.current_task || "")}</td>
    </tr>`).join("") ||
    `<tr><td colspan="4"><div class="empty"><div class="big">🛰️</div>No scans yet — add a target to begin.</div></td></tr>`;

  const topRows = (d.top_findings || []).map((f) => `
    <tr>
      <td>${sevBadge(f.severity)}</td>
      <td>${esc(f.title)}</td>
      <td class="mono dim">${esc(f.host || f.domain)}</td>
    </tr>`).join("") ||
    `<tr><td colspan="3"><div class="empty">No high/critical findings. Either clean, or not scanned yet.</div></td></tr>`;

  v.innerHTML = `
    <div class="stat-grid">
      <div class="stat"><div class="num">${d.targets}</div><div class="lbl">TARGETS</div></div>
      <div class="stat"><div class="num">${d.scans}</div><div class="lbl">SCANS</div></div>
      <div class="stat"><div class="num">${d.hosts}</div><div class="lbl">HOSTS FOUND</div></div>
      <div class="stat critical"><div class="num">${sev.critical || 0}</div><div class="lbl">CRITICAL</div></div>
      <div class="stat high"><div class="num">${sev.high || 0}</div><div class="lbl">HIGH</div></div>
      <div class="stat medium"><div class="num">${sev.medium || 0}</div><div class="lbl">MEDIUM</div></div>
    </div>
    <div class="two-col">
      <div class="panel">
        <div class="panel-head">Recent scans</div>
        <table><tbody>${recentRows}</tbody></table>
      </div>
      <div class="panel">
        <div class="panel-head">Top high-risk findings</div>
        <table><tbody>${topRows}</tbody></table>
      </div>
    </div>
    ${(d.schedules || []).length ? `
    <div class="panel" style="margin-top:14px">
      <div class="panel-head">Scheduled scans ⏱</div>
      <table><tbody>
        ${d.schedules.map((s) => `
          <tr>
            <td class="mono">${esc(s.domain)}</td>
            <td class="dim">every ${s.interval_hours % 1 ? s.interval_hours : Math.round(s.interval_hours)}h</td>
            <td class="dim">last: ${fmtTime(s.last_run)}</td>
            <td>next: <span class="mono">${fmtTime(s.next_run)}</span></td>
          </tr>`).join("")}
      </tbody></table>
    </div>` : ""}`;

  if ((d.recent_scans || []).some((s) => ["running", "queued"].includes(s.status))) {
    state.pollTimer = setInterval(() => renderDashboard(v), 2500);
  }
}

/* ================= targets ================= */
async function renderTargets(v) {
  const targets = await api("/targets");
  $("#topbar-actions").innerHTML =
    `<button class="btn primary" id="btn-add">+ Add target</button>`;
  $("#btn-add").onclick = openTargetModal;

  const rows = targets.map((t) => `
    <tr>
      <td>
        <div class="mono">${esc(t.domain)}</div>
        ${t.notes ? `<div class="dim" style="font-size:11.5px">${esc(t.notes)}</div>` : ""}
      </td>
      <td>${esc(t.name)}</td>
      <td class="mono">${t.scan_count}</td>
      <td>${t.high_findings ? `<span class="badge high">${t.high_findings} high+</span>` : '<span class="dim">—</span>'}</td>
      <td class="dim">${fmtTime(t.created_at)}</td>
      <td><div class="actions-cell">
        <button class="btn primary sm" onclick="openScanModal(${t.id}, '${esc(t.domain)}')">Scan</button>
        <button class="btn ghost sm" onclick="openScheduleModal(${t.id}, '${esc(t.domain)}')">⏱ Schedule</button>
        <button class="btn ghost sm" data-viewscans="${t.id}">Scans</button>
        <button class="btn danger sm" onclick="deleteTarget(${t.id}, '${esc(t.domain)}')">Delete</button>
      </div></td>
    </tr>`).join("") ||
    `<tr><td colspan="6"><div class="empty"><div class="big">🎯</div>No targets yet.<br>Add a domain you're authorized to test.</div></td></tr>`;

  v.innerHTML = `
    <div class="panel">
      <div class="panel-head">Targets</div>
      <table>
        <thead><tr><th>Domain</th><th>Name</th><th>Scans</th><th>Risk</th><th>Added</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;

  $$("[data-viewscans]", v).forEach((b) =>
    b.onclick = () => go("scans"));
}

async function deleteTarget(id, domain) {
  if (!confirm(`Delete target ${domain} and all its scans/findings?`)) return;
  try { await api(`/targets/${id}`, { method: "DELETE" }); toast("Target deleted"); }
  catch (e) { toast(e.message, true); }
  render();
}

/* ================= scans list ================= */
async function renderScans(v) {
  const scans = await api("/scans");
  $("#topbar-actions").innerHTML = "";
  const rows = scans.map((s) => {
    let scheduled = false;
    try { scheduled = !!(JSON.parse(s.options || "{}").scheduled); } catch {}
    return `
    <tr class="clickable" onclick="go('scan', ${s.id})">
      <td class="mono">#${s.id} ${scheduled ? '<span title="scheduled scan">⏱</span>' : ""}</td>
      <td class="mono">${esc(s.domain)}</td>
      <td>${statusBadge(s.status)}</td>
      <td><div class="progress-row">
        <div class="progress-track"><div class="progress-fill" style="width:${s.progress || 0}%"></div></div>
        <span class="progress-pct">${Math.round(s.progress || 0)}%</span></div></td>
      <td class="dim">${esc(s.current_task || "")}</td>
      <td class="dim">${fmtTime(s.started_at)}</td>
    </tr>`;
  }).join("") ||
    `<tr><td colspan="6"><div class="empty">No scans yet.</div></td></tr>`;

  v.innerHTML = `
    <div class="panel">
      <div class="panel-head">All scans</div>
      <table>
        <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Progress</th><th>Task</th><th>Started</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;

  if (scans.some((s) => ["running", "queued"].includes(s.status))) {
    state.pollTimer = setInterval(() => renderScans(v), 2500);
  }
}

/* ================= scan detail ================= */
async function renderScanDetail(v, id) {
  let scan;
  try { scan = await api(`/scans/${id}`); }
  catch (e) { v.innerHTML = `<div class="empty">Scan not found.</div>`; return; }

  $("#topbar-actions").innerHTML = `
    ${scan.status === "running" || scan.status === "queued"
      ? `<button class="btn danger" id="btn-cancel">Cancel</button>` : ""}
    ${scan.status === "done" ? `<button class="btn ghost" id="btn-diff">⇄ Diff with…</button>` : ""}
    <a class="btn ghost" href="/api/scans/${id}/report?format=html" target="_blank">HTML report</a>
    <a class="btn ghost" href="/api/scans/${id}/report?format=md">Markdown</a>
    <a class="btn ghost" href="/api/scans/${id}/report?format=csv">CSV</a>
    <a class="btn ghost" href="/api/scans/${id}/report?format=json">JSON</a>`;
  const cancelBtn = $("#btn-cancel");
  if (cancelBtn) cancelBtn.onclick = async () => {
    await api(`/scans/${id}/cancel`, { method: "POST" }); toast("Cancel requested");
  };
  const diffBtn = $("#btn-diff");
  if (diffBtn) diffBtn.onclick = () => openDiffModal(scan);

  const c = scan.counts || {};
  const sev = scan.severities || {};
  const stats = JSON.parse(scan.stats || "{}");

  const tabBtn = (key, label, count) => `
    <button class="tab ${state.scanTab === key ? "active" : ""}" data-tab="${key}">${label}${count != null ? ` (${count})` : ""}</button>`;

  v.innerHTML = `
    <div class="panel">
      <div class="panel-head" style="gap:14px">
        <span class="mono">${esc(scan.domain)}</span>${statusBadge(scan.status)}
        <span class="dim mono" style="margin-left:auto;font-weight:400">
          ${esc(scan.modules ? JSON.parse(scan.modules).join(" · ") : "")}
        </span>
      </div>
      <div style="padding:14px 16px">
        <div class="progress-row" style="margin-bottom:12px">
          <div class="progress-track" style="flex:1"><div class="progress-fill" style="width:${scan.progress || 0}%"></div></div>
          <span class="progress-pct">${Math.round(scan.progress || 0)}%</span>
        </div>
        <div class="two-col">
          <dl class="kv">
            <dt>current</dt><dd>${esc(scan.current_task || "—")}</dd>
            <dt>started</dt><dd>${fmtTime(scan.started_at)}</dd>
            <dt>finished</dt><dd>${fmtTime(scan.finished_at)}</dd>
          </dl>
          <dl class="kv">
            <dt>hosts</dt><dd>${c.hosts ?? 0}</dd>
            <dt>open ports</dt><dd>${c.ports ?? 0}</dd>
            <dt>http live</dt><dd>${c.http ?? 0}</dd>
            <dt>interesting urls</dt><dd>${c.urls ?? 0}</dd>
            <dt>secrets</dt><dd>${c.secrets ?? 0}</dd>
            <dt>emails</dt><dd>${c.emails ?? 0}</dd>
            <dt>findings</dt><dd>${sev.critical || 0}C / ${sev.high || 0}H / ${sev.medium || 0}M / ${sev.low || 0}L / ${sev.info || 0}I</dd>
          </dl>
        </div>
      </div>
      <div class="console" id="scan-log">${renderLog(scan.log)}</div>
    </div>
    <div class="panel">
      <div class="tabs">
        ${tabBtn("findings", "Findings", c.findings)}
        ${tabBtn("http", "HTTP", c.http)}
        ${tabBtn("ports", "Ports", c.ports)}
        ${tabBtn("hosts", "Hosts", c.hosts)}
        ${tabBtn("urls", "URLs", c.urls)}
        ${tabBtn("secrets", "Secrets", c.secrets)}
        ${tabBtn("emails", "Emails", c.emails)}
      </div>
      <div id="tab-body"><div class="empty">loading…</div></div>
    </div>`;

  $$(".tab", v).forEach((b) => b.onclick = () => {
    state.scanTab = b.dataset.tab;
    $$(".tab", v).forEach((x) => x.classList.toggle("active", x === b));
    loadTabBody(id);
  });
  loadTabBody(id);

  const logEl = $("#scan-log");
  if (logEl) logEl.scrollTop = logEl.scrollHeight;

  if (["running", "queued"].includes(scan.status)) {
    state.pollTimer = setInterval(() => renderScanDetail(v, id), 2000);
  }
}

function renderLog(log) {
  return esc(log || "waiting for output…")
    .split("\n")
    .map((l) => l.replace(/\[(\d\d:\d\d:\d\d)\]/, '<span class="ts">[$1]</span>'))
    .join("\n");
}

async function loadTabBody(id) {
  const body = $("#tab-body");
  if (!body) return;
  let data;
  try { data = await api(`/scans/${id}/results`); }
  catch { body.innerHTML = `<div class="empty">Results not available yet.</div>`; return; }

  const t = state.scanTab;
  if (t === "findings") {
    const order = ["critical", "high", "medium", "low", "info"];
    const rows = [...data.findings].sort(
      (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity)).map((f) => `
      <tr>
        <td>${sevBadge(f.severity)}</td>
        <td>
          <div>${esc(f.title)}</div>
          ${f.evidence ? `<div class="finding-evidence">${esc(f.evidence)}</div>` : ""}
          ${f.recommendation ? `<div class="finding-rec">↳ ${esc(f.recommendation)}</div>` : ""}
        </td>
        <td class="mono dim">${esc(f.host)}</td>
        <td class="dim">${esc(f.category)}</td>
      </tr>`).join("") ||
      `<tr><td colspan="4"><div class="empty">No findings.</div></td></tr>`;
    body.innerHTML = `<table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>Category</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  } else if (t === "http") {
    const rows = data.http.map((h) => `
      <tr>
        <td><a href="${esc(h.url)}" target="_blank" rel="noopener" class="mono" style="color:var(--accent);text-decoration:none">${esc(h.url)}</a></td>
        <td><span class="mono" style="color:${h.status < 300 ? "var(--green)" : h.status < 400 ? "var(--yellow)" : "var(--red)"}">${h.status ?? "—"}</span></td>
        <td>${esc(h.title || "")}</td>
        <td class="mono dim">${esc(h.server || "")}</td>
        <td class="dim">${esc((h.tech ? JSON.parse(h.tech) : []).join(", ") || "")}</td>
        <td class="mono dim">${h.header_score ?? "—"}</td>
        <td class="mono dim">${esc(h.tls_expires || "")}</td>
      </tr>`).join("") ||
      `<tr><td colspan="7"><div class="empty">No live HTTP endpoints.</div></td></tr>`;
    body.innerHTML = `<table>
      <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Tech</th><th>Header score</th><th>TLS expires</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  } else if (t === "ports") {
    const rows = data.ports.map((p) => `
      <tr>
        <td class="mono">${esc(p.ip)}</td>
        <td class="mono dim">${esc(p.hostname || "")}</td>
        <td class="mono" style="color:var(--accent)">${p.port}</td>
        <td>${esc(p.service || "?")}</td>
        <td class="mono dim">${esc(p.banner || "")}</td>
      </tr>`).join("") ||
      `<tr><td colspan="5"><div class="empty">No open ports found.</div></td></tr>`;
    body.innerHTML = `<table>
      <thead><tr><th>IP</th><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  } else if (t === "hosts") {
    const rows = data.hosts.map((h) => {
      let recs = "";
      try {
        const r = JSON.parse(h.records || "{}");
        recs = Object.entries(r).map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ");
      } catch {}
      return `<tr>
        <td class="mono">${esc(h.hostname)}</td>
        <td class="mono">${esc(h.ip || "—")}</td>
        <td class="dim">${esc(h.source || "")}</td>
        <td class="mono dim" style="font-size:11.5px">${esc(recs)}</td>
      </tr>`;
    }).join("") || `<tr><td colspan="4"><div class="empty">No hosts discovered.</div></td></tr>`;
    body.innerHTML = `<table>
      <thead><tr><th>Hostname</th><th>IP</th><th>Source</th><th>DNS records</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  } else if (t === "urls") {
    const rows = data.urls.map((u) => `
      <tr>
        <td>${u.interesting ? `<span class="badge high">★</span>` : ""}</td>
        <td class="mono">${esc(u.url)}</td>
        <td class="dim">${esc(u.source)}</td>
        <td class="mono dim">${u.status || "—"}</td>
        <td class="dim">${esc(u.note || u.content_type || "")}</td>
      </tr>`).join("") ||
      `<tr><td colspan="5"><div class="empty">No URLs discovered.</div></td></tr>`;
    body.innerHTML = `<table>
      <thead><tr><th>★</th><th>URL</th><th>Source</th><th>Status</th><th>Note</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  } else if (t === "secrets") {
    const rows = data.secrets.map((s) => `
      <tr>
        <td>${esc(s.kind)}</td>
        <td class="mono" style="color:var(--red)">${esc(s.value_masked)}</td>
        <td class="mono dim"><a href="${esc(s.url)}" target="_blank" rel="noopener" style="color:var(--text-dim)">${esc(s.url)}</a></td>
        <td class="mono dim" style="font-size:11.5px">${esc(s.context || "")}</td>
      </tr>`).join("") ||
      `<tr><td colspan="4"><div class="empty">No secrets found in client-side code.</div></td></tr>`;
    body.innerHTML = `<table>
      <thead><tr><th>Kind</th><th>Value</th><th>Found at</th><th>Context</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  } else if (t === "emails") {
    const rows = data.emails.map((e) => `
      <tr>
        <td class="mono">${esc(e.email)}</td>
        <td class="mono dim"><a href="${esc(e.source)}" target="_blank" rel="noopener" style="color:var(--text-dim)">${esc(e.source)}</a></td>
      </tr>`).join("") ||
      `<tr><td colspan="2"><div class="empty">No email addresses harvested.</div></td></tr>`;
    body.innerHTML = `<table>
      <thead><tr><th>Email</th><th>Source</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }
}

/* ================= all findings ================= */
async function renderFindings(v) {
  const scans = await api("/scans");
  $("#topbar-actions").innerHTML = "";
  let all = [];
  for (const s of scans.slice(0, 50)) {
    if (!["done", "error", "cancelled"].includes(s.status)) continue;
    try {
      const r = await api(`/scans/${s.id}/results`);
      r.findings.forEach((f) => { f.domain = s.domain; f.scan_id = s.id; });
      all.push(...r.findings);
    } catch {}
  }
  const order = ["critical", "high", "medium", "low", "info"];
  all.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));

  const chips = ["all", ...order].map((sev) =>
    `<button class="chip ${state.findingFilter === sev ? "active" : ""}" data-sev="${sev}">${sev}</button>`).join("");

  const filtered = all.filter((f) =>
    state.findingFilter === "all" || f.severity === state.findingFilter);

  const rows = filtered.map((f) => `
    <tr>
      <td>${sevBadge(f.severity)}</td>
      <td>${esc(f.title)}
        ${f.evidence ? `<div class="finding-evidence">${esc(f.evidence)}</div>` : ""}
        ${f.recommendation ? `<div class="finding-rec">↳ ${esc(f.recommendation)}</div>` : ""}
      </td>
      <td class="mono dim">${esc(f.host || f.domain)}</td>
      <td class="dim">${esc(f.category)}</td>
      <td class="mono clickable" onclick="go('scan', ${f.scan_id})">#${f.scan_id}</td>
    </tr>`).join("") ||
    `<tr><td colspan="5"><div class="empty">No findings${state.findingFilter !== "all" ? " at this severity" : ""}.</div></td></tr>`;

  v.innerHTML = `
    <div class="panel">
      <div class="filterbar">${chips}</div>
      <table>
        <thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>Category</th><th>Scan</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  $$(".chip", v).forEach((c) => c.onclick = () => {
    state.findingFilter = c.dataset.sev; renderFindings(v);
  });
}

/* ================= modals ================= */
function openTargetModal() {
  $("#modal-target").classList.remove("hidden");
  $("#t-domain").focus();
}
$$("[data-close]").forEach((b) =>
  b.onclick = () => b.closest(".modal-backdrop").classList.add("hidden"));
$$(".modal-backdrop").forEach((m) =>
  m.addEventListener("click", (e) => { if (e.target === m) m.classList.add("hidden"); }));

$("#t-save").onclick = async () => {
  const domain = $("#t-domain").value.trim();
  if (!domain) return toast("Domain is required", true);
  try {
    await api("/targets", {
      method: "POST",
      body: JSON.stringify({
        domain, name: $("#t-name").value.trim(), notes: $("#t-notes").value.trim(),
      }),
    });
    $("#modal-target").classList.add("hidden");
    $("#t-domain").value = $("#t-name").value = $("#t-notes").value = "";
    toast("Target added");
    render();
  } catch (e) { toast(e.message, true); }
};

function openScanModal(targetId, domain) {
  state.scanTargets = { id: targetId, domain };
  $("#s-target-hint").textContent = `Target: ${domain}`;
  $("#s-modules").innerHTML = MODULES.map(([key, desc]) => `
    <label class="module-item">
      <input type="checkbox" value="${key}" checked>
      <span><span class="m-name">${key}</span><div class="m-desc">${esc(desc)}</div></span>
    </label>`).join("");
  $("#modal-scan").classList.remove("hidden");
}

$("#s-launch").onclick = async () => {
  const modules = $$("#s-modules input:checked").map((i) => i.value);
  if (!modules.length) return toast("Select at least one module", true);
  const options = {
    top_ports: +$("#s-topports").value || 100,
    max_scan_ips: +$("#s-maxips").value || 25,
    ct: true, brute: true,
  };
  try {
    const r = await api("/scans", {
      method: "POST",
      body: JSON.stringify({ target_id: state.scanTargets.id, modules, options }),
    });
    $("#modal-scan").classList.add("hidden");
    toast(`Scan #${r.id} launched`);
    go("scan", r.id);
  } catch (e) { toast(e.message, true); }
};

/* ================= schedules ================= */
function openScheduleModal(targetId, domain) {
  state.scheduleTarget = { id: targetId, domain };
  $("#sch-hint").textContent = `Target: ${domain}`;
  $("#sch-interval").value = 24;
  $("#sch-webhook").value = "";
  $("#modal-schedule").classList.remove("hidden");
}

$("#sch-save").onclick = async () => {
  const hours = +$("#sch-interval").value;
  if (!hours || hours < 1) return toast("Interval must be ≥ 1 hour", true);
  try {
    await api("/schedules", {
      method: "POST",
      body: JSON.stringify({
        target_id: state.scheduleTarget.id,
        interval_hours: hours,
        modules: MODULES.map(([k]) => k),
        options: { top_ports: 100, max_scan_ips: 25, ct: true, brute: true },
        webhook_url: $("#sch-webhook").value.trim(),
      }),
    });
    $("#modal-schedule").classList.add("hidden");
    toast(`Scheduled — every ${hours}h`);
    render();
  } catch (e) { toast(e.message, true); }
};

/* ================= diff ================= */
async function openDiffModal(scan) {
  const others = (await api(`/scans?target_id=${scan.target_id}`))
    .filter((s) => s.id !== scan.id && ["done", "error", "cancelled"].includes(s.status))
    .sort((a, b) => b.id - a.id);
  if (!others.length) return toast("No other completed scans for this target", true);
  $("#d-hint").textContent = `Scan #${scan.id} (${scan.domain}) compared against:`;
  $("#d-other").innerHTML = others.map((s) =>
    `<option value="${s.id}">#${s.id} — ${fmtTime(s.started_at)} (${s.status})</option>`).join("");
  $("#d-result").innerHTML = "";
  $("#modal-diff").classList.remove("hidden");
  $("#d-run").onclick = async () => {
    const other = +$("#d-other").value;
    $("#d-result").innerHTML = `<div class="diff-empty">diffing…</div>`;
    try {
      const d = await api(`/diff?scan_a=${other}&scan_b=${scan.id}`);
      renderDiff(d);
    } catch (e) {
      $("#d-result").innerHTML = `<div class="diff-empty">diff failed: ${esc(e.message)}</div>`;
    }
  };
}

function renderDiff(d) {
  const item = (mark, text) =>
    `<div class="diff-item"><span class="diff-mark ${mark}">${mark === "add" ? "+" : mark === "del" ? "−" : "±"}</span><span>${text}</span></div>`;
  const section = (title, add, del, chg) => {
    const total = add.length + del.length + (chg ? chg.length : 0);
    let html = `<div class="diff-section"><h4>${title} (${total} changed)</h4>`;
    if (!total) html += `<div class="diff-empty">no changes</div>`;
    add.forEach((x) => html += item("add", x));
    del.forEach((x) => html += item("del", x));
    (chg || []).forEach((x) => html += item("chg", x));
    return html + "</div>";
  };
  const esc_ = esc;
  $("#d-result").innerHTML =
    `<div class="diff-empty" style="margin-top:8px">#${d.a.id} (${fmtTime(d.a.started_at)}) → #${d.b.id} (${fmtTime(d.b.started_at)})</div>` +
    section("Hosts",
      d.hosts.new.map((h) => esc_(`${h.hostname} (${h.ip})`)),
      d.hosts.removed.map((h) => esc_(`${h.hostname} (${h.ip})`))) +
    section("Open ports",
      d.ports.new.map((p) => esc_(`${p.ip}:${p.port} ${p.service || ""}`)),
      d.ports.removed.map((p) => esc_(`${p.ip}:${p.port} ${p.service || ""}`))) +
    section("Live endpoints",
      d.http.new.map((h) => `<a href="${esc_(h.url)}" target="_blank" rel="noopener" style="color:var(--accent)">${esc_(h.url)}</a> <span class="dim">(${h.status})</span>`),
      d.http.removed.map((h) => esc_(h.url)),
      d.http.changed.map((c) => esc_(`${c.url} ${c.from} → ${c.to}`))) +
    section("Secrets",
      d.secrets.new.map((s) => esc_(`${s.kind}: ${s.value_masked} @ ${s.url}`)),
      d.secrets.removed.map((s) => esc_(`${s.kind}: ${s.value_masked}`))) +
    section("Findings",
      d.findings.new.map((f) => `${sevBadge(f.severity)} <span>${esc_(f.title)} <span class="dim">${esc_(f.host || "")}</span></span>`),
      d.findings.resolved.map((f) => `${sevBadge(f.severity)} <span>${esc_(f.title)} <span class="dim">${esc_(f.host || "")}</span></span>`)) +
    section("Emails",
      d.emails.new.map((e) => esc_(e)),
      d.emails.removed.map((e) => esc_(e)));
}

/* expose for inline handlers */
window.go = go;
window.openScanModal = openScanModal;
window.openScheduleModal = openScheduleModal;
window.deleteTarget = deleteTarget;

/* boot */
go("dashboard");
