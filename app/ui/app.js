// BaazCyber Antivirus: UI logic
import { buildReport } from "./report.js";

const T = window.__TAURI__;
const invoke = T.core.invoke;
const listen = T.event.listen;
const dialog = T.dialog;

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};

// ── 3D icons ──────────────────────────────────────────
// [highlight, base, extrusion]
const TONES = {
  emerald: ["#7dffd2", "#10b981", "#065f46"],
  azure:   ["#8fdcff", "#2563eb", "#1e3a8a"],
  amber:   ["#ffe08a", "#f59e0b", "#92400e"],
  indigo:  ["#c4b5fd", "#6366f1", "#312e81"],
  rose:    ["#ffa3b5", "#e11d48", "#881337"],
  cyan:    ["#a5f3fc", "#0891b2", "#164e63"],
  slate:   ["#e2e8f0", "#64748b", "#1e293b"],
};
const G = {
  shield: '<path d="M12 3 19 6v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="m9 11.5 2 2 4-4"/>',
  radar: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3.5"/><path d="M12 12 17.7 6.3"/>',
  vault: '<rect x="4" y="5" width="16" height="15" rx="2.5"/><circle cx="12" cy="12.5" r="3"/><path d="M12 9.5V8M15 12.5h1.5"/>',
  clock: '<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8"/>',
  bolt: '<path d="M13 3 5 13.5h6L10 21l8-10.5h-6z"/>',
  drive: '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M5 13l2.5-7h9L19 13"/><path d="M16.5 16.5h.01"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 14h6M9 17h4"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  rocket: '<path d="M12 3c3 2 5 5.5 5 9.5L15 16H9l-2-3.5C7 8.5 9 5 12 3z"/><circle cx="12" cy="10" r="1.8"/><path d="M9 16l-2 4 3-1M15 16l2 4-3-1"/>',
  files: '<path d="M9 3h6l4 4v9a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M15 3v4h4M4 8v11a2 2 0 0 0 2 2h8"/>',
  bug: '<path d="M8 9a4 4 0 0 1 8 0v5a4 4 0 0 1-8 0z"/><path d="M12 9v9M4 12h4M16 12h4M5 7l3 2M19 7l-3 2M5 18l3-2M19 18l-3-2"/>',
  db: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
  brain: '<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v5h-5"/>',
  alert: '<path d="M12 4 21 20H3z"/><path d="M12 10v4M12 17h.01"/>',
  check: '<path d="m5 12 5 5 9-10"/>',
  info: '<circle cx="12" cy="12" r="8"/><path d="M12 11v5M12 8h.01"/>',
};

document.body.insertAdjacentHTML("beforeend", `<svg class="defs"><defs>${Object.entries(TONES).map(([k, [a, b]]) =>
  `<linearGradient id="tg-${k}" x1="0" y1="0" x2=".4" y2="1"><stop offset="0" stop-color="${a}"/><stop offset="1" stop-color="${b}"/></linearGradient>`).join("")}</defs></svg>`);

function icon3d(name, tone = "azure") {
  const [, base, depth] = TONES[tone] || TONES.azure;
  const glyph = G[name] || G.shield;
  return `<svg viewBox="0 0 64 64" aria-hidden="true">
    <ellipse class="glow" cx="32" cy="58" rx="22" ry="5" fill="${base}"/>
    <rect x="6" y="11" width="52" height="48" rx="15" fill="${depth}"/>
    <rect x="6" y="5" width="52" height="48" rx="15" fill="url(#tg-${tone})"/>
    <rect x="6.5" y="5.5" width="51" height="47" rx="14.5" fill="none" stroke="#fff" stroke-opacity=".35"/>
    <path d="M21 8h22a12 12 0 0 1 12 12v1c-10-6-36-6-46 4v-5A12 12 0 0 1 21 8z" fill="#fff" opacity=".25"/>
    <g transform="translate(17 14.5) scale(1.25)" fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2">
      <g stroke="${depth}" stroke-opacity=".55" transform="translate(0 1.3)">${glyph}</g>
      <g stroke="#fff">${glyph}</g>
    </g></svg>`;
}
function paintIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach(n => { n.innerHTML = icon3d(n.dataset.icon, n.dataset.tone); n.removeAttribute("data-icon"); });
}
paintIcons();

// 3D tilt on the tool tiles
document.querySelectorAll(".tile").forEach(t => {
  t.addEventListener("mousemove", (e) => {
    const r = t.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - .5, y = (e.clientY - r.top) / r.height - .5;
    t.style.transform = `rotateX(${(-y * 12).toFixed(2)}deg) rotateY(${(x * 14).toFixed(2)}deg) translateY(-3px)`;
  });
  t.addEventListener("mouseleave", () => { t.style.transform = ""; });
});

// ── Title bar ─────────────────────────────────────────
const win = T.window?.getCurrentWindow?.();
if (win) {
  const maxIcon = (max) => $("#tbMax").innerHTML = max
    ? '<svg viewBox="0 0 12 12"><rect x="2" y="4" width="6" height="6" rx="1.2"/><path d="M4.5 4V3.2C4.5 2.5 5 2 5.7 2h3.1c.7 0 1.2.5 1.2 1.2v3.1c0 .7-.5 1.2-1.2 1.2H8"/></svg>'
    : '<svg viewBox="0 0 12 12"><rect x="2" y="2" width="8" height="8" rx="1.5"/></svg>';
  const syncMax = async () => { try { maxIcon(await win.isMaximized()); } catch {} };
  $("#tbMin").onclick = () => win.minimize();
  $("#tbMax").onclick = async () => { await win.toggleMaximize(); syncMax(); };
  $("#tbClose").onclick = () => win.close();
  win.onResized?.(syncMax);
  syncMax();
}

// ── State ─────────────────────────────────────────────
const state = { scanning: false, lastDetections: [] };
const prefs = { confirm: store.get("bc.prefConfirm", true), history: store.get("bc.prefHistory", true) };
$("#prefConfirm").checked = prefs.confirm;
$("#prefHistory").checked = prefs.history;
$("#prefConfirm").onchange = (e) => { prefs.confirm = e.target.checked; store.set("bc.prefConfirm", prefs.confirm); };
$("#prefHistory").onchange = (e) => { prefs.history = e.target.checked; store.set("bc.prefHistory", prefs.history); };

// ── Navigation ────────────────────────────────────────
function show(view) {
  document.querySelectorAll(".view").forEach(v => v.hidden = v.dataset.view !== view);
  document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === view));
  if (view === "quarantine") loadQuarantine();
  if (view === "history") loadHistory();
}
document.querySelectorAll(".nav-item").forEach(n => n.addEventListener("click", () => show(n.dataset.view)));

// ── Toast ─────────────────────────────────────────────
let toastTimer;
function toast(msg, kind = "") {
  const t = $("#toast");
  t.textContent = msg; t.className = `toast ${kind}`; t.hidden = false;
  requestAnimationFrame(() => t.classList.add("show"));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.classList.remove("show"); setTimeout(() => t.hidden = true, 300); }, 3200);
}

// ── Status, shield and score ──────────────────────────
function setStatus(kind, title, sub) {
  $("#statusTitle").textContent = title;
  $("#statusSub").textContent = sub;
  $("#statusEyebrow").textContent = { ok: "PROTECTION ACTIVE", scanning: "SCAN IN PROGRESS", threat: "ACTION NEEDED" }[kind];
  $("#stage").className = `stage ${kind}`;
  const guard = { ok: ["Protected", "shield", "emerald"], scanning: ["Scanning…", "radar", "azure"], threat: ["At risk", "alert", "rose"] }[kind];
  $("#guardCard").className = `guard ${kind}`;
  $("#tbChip").className = `tb-chip ${kind}`;
  $("#tbChipText").textContent = guard[0];
  $("#guardTitle").textContent = guard[0];
  $("#guardIcon").innerHTML = icon3d(guard[1], guard[2]);
  $(".hero-card").className = `hero-card ${kind === "ok" ? "" : kind}`;
}

function timeAgo(ms) {
  const m = Math.round((Date.now() - ms) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} hour${h === 1 ? "" : "s"} ago`;
  const d = Math.round(h / 24);
  return `${d} day${d === 1 ? "" : "s"} ago`;
}

function activeThreats() { return state.lastDetections.filter(d => d.threat && d.threat.kind !== "test" && !d.done); }

function computeScore() {
  const last = store.get("bc.lastScan", null);
  let score = 100;
  if (!last) score -= 20;
  else if (Date.now() - last.at > 7 * 864e5) score -= 15;
  score -= Math.min(60, activeThreats().length * 25);
  return Math.max(0, score);
}

function updateScore() {
  const last = store.get("bc.lastScan", null);
  const score = computeScore();
  $("#scoreNum").textContent = score;
  $("#scoreProg").style.strokeDashoffset = (314.16 * (1 - score / 100)).toFixed(1);
  $("#lastScanText").textContent = last
    ? `Last scan: ${last.label}, ${timeAgo(last.at)} · ${last.files.toLocaleString()} files · ${last.threats} threat${last.threats === 1 ? "" : "s"}`
    : "No scan yet. Run a Smart Scan to get your full score.";
  if (!state.scanning && !activeThreats().length) {
    setStatus("ok", "You're Protected", last ? "No active threats. BaazCyber is guarding your files." : "BaazCyber is ready. Run a Smart Scan to check the places malware hides.");
  }
}

// ── Startup ───────────────────────────────────────────
async function init() {
  try {
    const n = (await invoke("signature_count")) + 2;
    $("#statSig").textContent = n.toLocaleString();
    $("#sigText").textContent = `${n.toLocaleString()} known threats`;
  } catch {}
  try {
    const v = await T.app.getVersion();
    $("#verText").textContent = `Version ${v} · FlightCoders`;
    $("#aboutVer").textContent = `v${v}`;
  } catch {}
  const last = store.get("bc.lastScan", null);
  if (last) $("#statLastFiles").textContent = last.files.toLocaleString(), $("#statThreats").textContent = last.threats;
  refreshQuarantineBadge();
  updateScore();
  setTimeout(checkForUpdateOnStart, 4000);
}

async function checkForUpdateOnStart() {
  if (!T.updater) return;
  try {
    const update = await T.updater.check();
    if (!update) return;
    pendingUpdate = update;
    $("#updateText").textContent = `Version ${update.version} is ready to install.`;
    $("#installUpdateBtn").hidden = false;
    const ok = await dialog.ask(`BaazCyber Antivirus ${update.version} is ready. Install it now? The app will restart.`, { title: "Update available", kind: "info" });
    if (ok) { toast("Downloading the update…"); await update.downloadAndInstall(); }
  } catch {}
}

// ── Scanning ──────────────────────────────────────────
let unlisten, ticker;

async function runScan(paths, label) {
  if (state.scanning) return toast("A scan is already running");
  state.scanning = true;
  state.lastDetections = [];

  show("scan");
  $("#scanTitle").textContent = label;
  $("#scanPath").textContent = paths.length ? paths.join("  ·  ") : "Downloads, Desktop, Documents, Temp and Startup";
  $("#scanBar").hidden = false;
  $("#runScanBtn").hidden = $("#pickFolderBtn").hidden = true;
  $("#stopScanBtn").hidden = false;
  $("#results").innerHTML = "";
  $("#resultsBar").hidden = true;
  $("#scanCount").textContent = $("#scanThreats").textContent = $("#scanSpeed").textContent = "0";
  $("#scanTime").textContent = "0:00";
  $("#scanFile").textContent = "Starting…";
  setStatus("scanning", "Scanning…", `${label} in progress. You can keep using your computer.`);

  const started = Date.now();
  let files = 0;
  state.scanPaths = paths.length ? paths : (await invoke("quick_targets").catch(() => [])).map(t => t.path);
  ticker = setInterval(() => {
    const s = (Date.now() - started) / 1000;
    $("#scanTime").textContent = `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
    $("#scanSpeed").textContent = s > 0.5 ? Math.round(files / s).toLocaleString() : "0";
  }, 250);

  unlisten = await listen("scan:progress", (e) => {
    const p = e.payload;
    files = p.files;
    $("#scanCount").textContent = p.files.toLocaleString();
    $("#scanThreats").textContent = p.threats.toLocaleString();
    $("#scanFile").textContent = p.current;
  });

  try {
    const summary = await invoke("start_scan", { paths });
    state.lastDetections = summary.detections;
    finishScan(summary, label);
  } catch (err) {
    toast("Scan failed: " + err, "err");
    updateScore();
  } finally {
    if (unlisten) unlisten();
    clearInterval(ticker);
    state.scanning = false;
    $("#scanBar").hidden = true;
    $("#runScanBtn").hidden = $("#pickFolderBtn").hidden = false;
    $("#stopScanBtn").hidden = true;
  }
}

function finishScan(summary, label) {
  const real = summary.detections.filter(d => d.threat && d.threat.kind !== "test");
  $("#statLastFiles").textContent = summary.files.toLocaleString();
  $("#statThreats").textContent = summary.detections.length;

  const record = { at: Date.now(), label, files: summary.files, threats: summary.detections.length, seconds: summary.seconds, cancelled: summary.cancelled };
  store.set("bc.lastScan", record);
  if (prefs.history) store.set("bc.history", [record, ...store.get("bc.history", [])].slice(0, 50));
  state.report = { ...record, bytes: summary.bytes, paths: state.scanPaths || [] };
  saveReportData();

  const list = $("#results");
  list.innerHTML = "";
  if (!summary.detections.length) {
    list.appendChild(el("div", "empty-state",
      `<span class="ic lg" data-icon="check" data-tone="emerald"></span>
       <p>${summary.cancelled ? "Scan stopped. Nothing found in the files checked." : `No threats found in ${summary.files.toLocaleString()} files. You're clean.`}</p>`));
    paintIcons(list);
    updateScore();
    toast(summary.cancelled ? "Scan stopped" : "Scan complete: no threats", "ok");
    return;
  }

  summary.detections.forEach(d => list.appendChild(threatRow(d)));
  paintIcons(list);
  $("#resultsBar").hidden = false;
  $("#resultsSummary").innerHTML = `<b>${summary.detections.length}</b> threat${summary.detections.length === 1 ? "" : "s"} found in ${summary.files.toLocaleString()} files`;
  $("#quarantineAllBtn").hidden = real.length === 0;
  updateScore();
  if (real.length) setStatus("threat", `${real.length} Threat${real.length === 1 ? "" : "s"} Found`, "Review the threats and move them to quarantine.");
  else setStatus("ok", "Test File Detected", "Only harmless antivirus test files were found.");
  toast(`${summary.detections.length} threat${summary.detections.length === 1 ? "" : "s"} found`, real.length ? "err" : "ok");
}

const SEV_TONE = { critical: "rose", high: "rose", medium: "amber", low: "emerald" };

function threatRow(d) {
  const t = d.threat, sev = t.severity;
  const row = el("div", `threat ${sev}`);
  row.innerHTML = `
    <span class="ic sm" data-icon="${sev === "low" ? "info" : "alert"}" data-tone="${SEV_TONE[sev] || "amber"}"></span>
    <div class="threat-info">
      <div class="name">${esc(t.name)}<span class="tag ${esc(sev)}">${esc(sev)}</span></div>
      <div class="path" title="${esc(d.path)}">${esc(d.path)}</div>
      <div class="why">${esc(t.reasons[0] || "")}</div>
    </div>
    <div class="threat-actions"></div>`;
  const actions = row.querySelector(".threat-actions");
  if (t.kind !== "test") {
    const q = el("button", "btn3d primary sm", "Quarantine");
    q.onclick = async () => {
      if (await quarantineOne(d)) { row.style.opacity = ".45"; q.disabled = true; q.textContent = "Quarantined"; toast("Moved to quarantine", "ok"); }
    };
    actions.appendChild(q);
  } else {
    actions.appendChild(el("span", "tag low", "harmless test"));
  }
  return row;
}

async function quarantineOne(d) {
  try {
    await invoke("quarantine_file", { path: d.path, sha256: d.sha256, name: d.threat.name, reasons: d.threat.reasons });
    d.done = true;
    saveReportData();
    refreshQuarantineBadge();
    updateScore();
    return true;
  } catch (err) { toast("Couldn't quarantine: " + err, "err"); return false; }
}

$("#quarantineAllBtn").onclick = async () => {
  const real = activeThreats();
  if (!real.length) return;
  if (prefs.confirm) {
    const ok = await dialog.ask(`Move ${real.length} threat${real.length === 1 ? "" : "s"} to quarantine?`, { title: "BaazCyber Antivirus", kind: "warning" });
    if (!ok) return;
  }
  let done = 0;
  for (const d of real) if (await quarantineOne(d)) done++;
  toast(`${done} file${done === 1 ? "" : "s"} quarantined`, "ok");
  show("quarantine");
};

// ── Scan types ────────────────────────────────────────
async function quickFolders(match) {
  try { return (await invoke("quick_targets")).filter(t => match(t.label.toLowerCase())).map(t => t.path); } catch { return []; }
}
const ACTIONS = {
  quick: () => runScan([], "Smart Scan"),
  full: async () => {
    const drive = await invoke("system_drive").catch(() => "C:\\");
    runScan([drive], "Full Scan");
  },
  folder: async () => {
    const picked = await dialog.open({ directory: true, multiple: false, title: "Choose a folder or drive to scan" });
    if (picked) runScan([picked], "Folder Scan");
  },
  file: async () => {
    const picked = await dialog.open({ directory: false, multiple: false, title: "Choose a file to scan" });
    if (picked) runScan([picked], "File Scan");
  },
  downloads: async () => {
    const p = await quickFolders(l => l === "downloads");
    p.length ? runScan(p, "Downloads Scan") : toast("Downloads folder not found", "err");
  },
  startup: async () => {
    const p = await quickFolders(l => l.startsWith("startup"));
    p.length ? runScan(p, "Startup Scan") : toast("No startup folders found", "err");
  },
};
document.querySelectorAll(".tile").forEach(t => t.addEventListener("click", () => ACTIONS[t.dataset.act]()));
$("#quickScanBtn").onclick = ACTIONS.quick;
$("#runScanBtn").onclick = ACTIONS.quick;
$("#fullScanBtn").onclick = ACTIONS.full;
$("#pickFolderBtn").onclick = ACTIONS.folder;
$("#stopScanBtn").onclick = () => invoke("cancel_scan");

// ── Quarantine ────────────────────────────────────────
async function loadQuarantine() {
  const list = $("#qList");
  let entries = [];
  try { entries = await invoke("list_quarantine"); } catch {}
  list.innerHTML = "";
  $("#statQ").textContent = entries.length;
  if (!entries.length) {
    list.appendChild(el("div", "empty-state", `<span class="ic lg" data-icon="vault" data-tone="amber"></span><p>Quarantine is empty.</p>`));
    paintIcons(list);
    return;
  }
  entries.forEach(e => {
    const row = el("div", "qentry");
    row.innerHTML = `
      <span class="ic sm" data-icon="vault" data-tone="amber"></span>
      <div class="meta">
        <div class="name">${esc(e.threat_name)}</div>
        <div class="path" title="${esc(e.original_path)}">${esc(e.original_path)}</div>
        <div class="when">${esc(new Date(e.quarantined_at * 1000).toLocaleString())}</div>
      </div>
      <div class="threat-actions"></div>`;
    const actions = row.querySelector(".threat-actions");
    const restore = el("button", "btn3d ghost sm", "Restore");
    restore.onclick = async () => {
      try { await invoke("restore_quarantine", { id: e.id }); toast("Restored", "ok"); loadQuarantine(); refreshQuarantineBadge(); }
      catch (err) { toast("Couldn't restore: " + err, "err"); }
    };
    const del = el("button", "btn3d danger sm", "Delete");
    del.onclick = async () => {
      try { await invoke("delete_quarantine", { id: e.id }); toast("Deleted for good", "ok"); loadQuarantine(); refreshQuarantineBadge(); }
      catch (err) { toast("Couldn't delete: " + err, "err"); }
    };
    actions.append(restore, del);
    list.appendChild(row);
  });
  paintIcons(list);
}

async function refreshQuarantineBadge() {
  try {
    const n = (await invoke("list_quarantine")).length;
    $("#qBadge").textContent = n;
    $("#qBadge").hidden = n === 0;
    $("#statQ").textContent = n;
  } catch {}
}

// ── History ───────────────────────────────────────────
function loadHistory() {
  const list = $("#historyList");
  const items = store.get("bc.history", []);
  list.innerHTML = "";
  if (!items.length) {
    list.appendChild(el("div", "empty-state", `<span class="ic lg" data-icon="clock" data-tone="indigo"></span><p>No scans recorded yet.</p>`));
  }
  items.forEach(h => {
    const row = el("div", "hist");
    row.innerHTML = `
      <span class="ic sm" data-icon="${h.threats ? "alert" : "check"}" data-tone="${h.threats ? "rose" : "emerald"}"></span>
      <div class="meta"><div class="name">${esc(h.label)}${h.cancelled ? '<span class="tag medium">stopped</span>' : ""}</div>
        <div class="when">${esc(new Date(h.at).toLocaleString())}</div></div>
      <div class="nums">
        <div><b>${h.files.toLocaleString()}</b><span>files</span></div>
        <div class="${h.threats ? "bad" : ""}"><b>${h.threats}</b><span>threats</span></div>
        <div><b>${h.seconds.toFixed(1)}s</b><span>time</span></div>
      </div>`;
    list.appendChild(row);
  });
  paintIcons(list);
}
$("#clearHistoryBtn").onclick = () => { store.set("bc.history", []); loadHistory(); toast("History cleared", "ok"); };

// ── PDF report ────────────────────────────────────────
// The last scan is kept (up to 500 findings) so its report can still be saved after the app restarts.
function saveReportData() {
  if (!state.report) return;
  const detections = state.lastDetections.slice(0, 500).map(d => ({
    path: d.path, done: !!d.done,
    threat: { name: d.threat.name, kind: d.threat.kind, severity: d.threat.severity, reasons: d.threat.reasons.slice(0, 1) },
  }));
  store.set("bc.lastReport", { ...state.report, detections });
  document.querySelectorAll(".report-btn").forEach(b => b.hidden = false);
}

async function saveReport() {
  const data = store.get("bc.lastReport", null);
  if (!data) return toast("Run a scan first, then save its report");
  const signatures = (await invoke("signature_count").catch(() => 0)) + 2;
  const id = `BC-${data.at.toString(36).toUpperCase()}`;
  const pdf = buildReport({ ...data, id, signatures, score: computeScore() });
  const day = new Date(data.at).toISOString().slice(0, 10);
  const path = await dialog.save({ title: "Save security report", defaultPath: `BaazCyber-Security-Report-${day}.pdf`, filters: [{ name: "PDF document", extensions: ["pdf"] }] });
  if (!path) return;
  try {
    await invoke("save_report", { path, data: Array.from(pdf) });
    if (await dialog.ask("Your security report was saved. Open it now?", { title: "BaazCyber Antivirus", kind: "info" })) {
      await invoke("open_report", { path });
    }
  } catch (err) { toast("Couldn't save the report: " + err, "err"); }
}
document.querySelectorAll(".report-btn").forEach(b => b.addEventListener("click", saveReport));
if (store.get("bc.lastReport", null)) document.querySelectorAll(".report-btn").forEach(b => b.hidden = false);

// ── Updates ───────────────────────────────────────────
let pendingUpdate = null;
$("#checkUpdateBtn").onclick = async () => {
  const btn = $("#checkUpdateBtn");
  if (!T.updater) return $("#updateText").textContent = "Updates are managed by the Microsoft Store on this copy.";
  btn.disabled = true; btn.textContent = "Checking…";
  try {
    pendingUpdate = await T.updater.check();
    if (pendingUpdate) {
      $("#updateText").textContent = `Version ${pendingUpdate.version} is ready to install.`;
      $("#installUpdateBtn").hidden = false;
    } else {
      $("#updateText").textContent = "You have the latest version.";
    }
  } catch (err) {
    $("#updateText").textContent = "Couldn't check for updates: " + err;
  } finally { btn.disabled = false; btn.textContent = "Check for updates"; }
};
$("#installUpdateBtn").onclick = async () => {
  if (!pendingUpdate) return;
  $("#installUpdateBtn").disabled = true;
  $("#updateText").textContent = "Downloading the update…";
  try { await pendingUpdate.downloadAndInstall(); }
  catch (err) { $("#updateText").textContent = "Update failed: " + err; $("#installUpdateBtn").disabled = false; }
};

init();
