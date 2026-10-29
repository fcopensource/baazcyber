// BaazCyber Antivirus — UI logic
const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;
const dialog = window.__TAURI__.dialog;

const $ = (s) => document.querySelector(s);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls)  e.className = cls;
  if (html != null) e.innerHTML = html;
  return e;
};

// SVG defs for the ring gradient
document.body.insertAdjacentHTML("beforeend",
  `<svg class="defs"><defs>
    <linearGradient id="grad" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#22c55e"/>
      <stop offset="1" stop-color="#06b6d4"/>
    </linearGradient>
   </defs></svg>`);

const state = { scanning: false, lastDetections: [] };

// ── Navigation ────────────────────────────────────────
function show(view) {
  document.querySelectorAll(".view").forEach(v => v.hidden = v.dataset.view !== view);
  document.querySelectorAll(".nav-item").forEach(n =>
    n.classList.toggle("active", n.dataset.view === view));
  if (view === "quarantine") loadQuarantine();
}
document.querySelectorAll(".nav-item").forEach(n =>
  n.addEventListener("click", () => show(n.dataset.view)));

// ── Toast ─────────────────────────────────────────────
let toastTimer;
function toast(msg, kind = "") {
  const t = $("#toast");
  t.textContent = msg; t.className = `toast ${kind}`; t.hidden = false;
  requestAnimationFrame(() => t.classList.add("show"));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => t.hidden = true, 300);
  }, 3200);
}

// ── Shield/status ─────────────────────────────────────
const shieldWrap = $(".shield-wrap");

function setStatus(kind, title, sub) {
  $("#statusTitle").textContent = title;
  $("#statusSub").textContent   = sub;
  shieldWrap.className = "shield-wrap";
  if (kind === "threat")   shieldWrap.classList.add("shield-stage", "threat");
  if (kind === "scanning") shieldWrap.classList.add("shield-stage", "scanning");
  const ring = $("#ringProg");
  if (kind === "threat") {
    ring.style.stroke = "var(--red)";
  } else {
    ring.style.stroke = "";
  }
}

function setShieldScanning(on) {
  if (on) {
    shieldWrap.classList.add("shield-stage", "scanning");
    $("#sweep").hidden = false;
  } else {
    shieldWrap.classList.remove("shield-stage", "scanning");
    $("#sweep").hidden = true;
  }
}

// ── Startup ───────────────────────────────────────────
async function init() {
  try {
    const count = await invoke("signature_count");
    $("#statSig").textContent  = (count + 2).toLocaleString();
    $("#sigText").textContent  = `${(count + 2).toLocaleString()} known threats`;
  } catch {}
  refreshQuarantineBadge();
}

// ── Scanning ──────────────────────────────────────────
const SEV_ICON = {
  critical: `<svg viewBox="0 0 24 24"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>`,
  high:     `<svg viewBox="0 0 24 24"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>`,
  medium:   `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>`,
  low:      `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg>`,
};

let unlisten;

async function runScan(paths, label) {
  if (state.scanning) return;
  state.scanning = true;
  state.lastDetections = [];

  show("scan");
  $("#scanTitle").textContent = label;
  $("#scanPath").textContent  = paths.length ? paths.join("  ·  ") : "Checking the usual places malware hides";
  $("#scanBar").hidden       = false;
  $("#runScanBtn").hidden    = true;
  $("#pickFolderBtn").hidden = true;
  $("#stopScanBtn").hidden   = false;
  $("#results").innerHTML    = "";
  $("#resultsBar").hidden    = true;
  $("#scanCount").textContent   = "0";
  $("#scanThreats").textContent = "0";
  $("#scanFile").textContent    = "Starting…";
  setShieldScanning(true);

  unlisten = await listen("scan:progress", (e) => {
    const p = e.payload;
    $("#scanCount").textContent   = p.files.toLocaleString();
    $("#scanThreats").textContent = p.threats.toLocaleString();
    $("#scanFile").textContent    = p.current;
  });

  try {
    const summary = await invoke("start_scan", { paths });
    state.lastDetections = summary.detections;
    finishScan(summary, label);
  } catch (err) {
    toast("Scan failed: " + err, "err");
  } finally {
    if (unlisten) unlisten();
    state.scanning = false;
    $("#scanBar").hidden       = true;
    $("#runScanBtn").hidden    = false;
    $("#pickFolderBtn").hidden = false;
    $("#stopScanBtn").hidden   = true;
    setShieldScanning(false);
  }
}

function finishScan(summary, label) {
  $("#statLastFiles").textContent = summary.files.toLocaleString();
  const real = summary.detections.filter(d => d.threat && d.threat.kind !== "test");
  $("#statThreats").textContent = summary.detections.length;
  const list = $("#results");
  list.innerHTML = "";

  if (!summary.detections.length) {
    list.appendChild(el("div", "empty-state",
      `<svg viewBox="0 0 24 24" width="48" height="48"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
       <p>${summary.cancelled ? "Scan stopped." : "No threats found — you're clean."}</p>`));
    setStatus("ok", "You're Protected",
      `Scanned ${summary.files.toLocaleString()} files in ${summary.seconds.toFixed(1)}s. Nothing suspicious.`);
    return;
  }

  summary.detections.forEach(d => list.appendChild(threatRow(d)));
  $("#resultsBar").hidden = false;
  $("#resultsSummary").innerHTML =
    `<b>${summary.detections.length}</b> threat${summary.detections.length === 1 ? "" : "s"} found in ${summary.files.toLocaleString()} files`;
  $("#quarantineAllBtn").hidden = real.length === 0;
  setStatus(real.length ? "threat" : "ok",
    real.length ? `${real.length} Threat${real.length === 1 ? "" : "s"} Found` : "Test File Detected",
    real.length ? "Review threats below and quarantine anything suspicious." : "Only harmless test files were found.");
}

function threatRow(d) {
  const t = d.threat, sev = t.severity;
  const row = el("div", `threat ${sev}`);
  row.innerHTML = `
    <div class="sev">${SEV_ICON[sev] || SEV_ICON.low}</div>
    <div class="threat-info">
      <div class="name">${t.name}<span class="tag">${sev}</span></div>
      <div class="path" title="${d.path}">${d.path}</div>
      <div class="why">${t.reasons[0] || ""}</div>
    </div>
    <div class="threat-actions"></div>`;
  const actions = row.querySelector(".threat-actions");
  if (t.kind !== "test") {
    const q = el("button", "btn primary", "Quarantine");
    q.onclick = async () => {
      try {
        await invoke("quarantine_file", { path: d.path, sha256: d.sha256, name: t.name, reasons: t.reasons });
        row.style.opacity = ".4";
        q.disabled = true; q.textContent = "Quarantined";
        toast("Moved to quarantine", "ok");
        refreshQuarantineBadge();
      } catch (err) { toast("Couldn't quarantine: " + err, "err"); }
    };
    actions.appendChild(q);
  } else {
    actions.appendChild(el("span", "tag low", "harmless test"));
  }
  return row;
}

$("#quarantineAllBtn").onclick = async () => {
  const real = state.lastDetections.filter(d => d.threat && d.threat.kind !== "test");
  let done = 0;
  for (const d of real) {
    try {
      await invoke("quarantine_file", { path: d.path, sha256: d.sha256, name: d.threat.name, reasons: d.threat.reasons });
      done++;
    } catch {}
  }
  toast(`${done} file${done === 1 ? "" : "s"} quarantined`, "ok");
  refreshQuarantineBadge();
  show("quarantine");
};

// ── Scan buttons ──────────────────────────────────────
$("#quickScanBtn").onclick  = () => runScan([], "Quick Scan");
$("#runScanBtn").onclick    = () => runScan([], "Quick Scan");
$("#stopScanBtn").onclick   = () => invoke("cancel_scan");

$("#fullScanBtn").onclick = async () => {
  const picked = await dialog.open({ directory: true, multiple: false, title: "Choose what the full scan covers" });
  runScan(picked ? [picked] : [], picked ? "Full Scan" : "Quick Scan");
};

async function chooseFolder() {
  const picked = await dialog.open({ directory: true, multiple: false, title: "Choose a folder to scan" });
  if (picked) runScan([picked], "Custom Scan");
}
$("#customScanBtn").onclick = chooseFolder;
$("#pickFolderBtn").onclick = chooseFolder;

// ── Quarantine ────────────────────────────────────────
async function loadQuarantine() {
  const list = $("#qList");
  let entries = [];
  try { entries = await invoke("list_quarantine"); } catch {}
  list.innerHTML = "";
  $("#statQ").textContent = entries.length;
  if (!entries.length) {
    list.appendChild(el("div", "empty-state",
      `<svg viewBox="0 0 24 24" width="48" height="48"><rect x="4" y="5" width="16" height="16" rx="2"/><path d="M4 9h16M9 3v4m6-4v4"/></svg>
       <p>Quarantine is empty.</p>`));
    return;
  }
  entries.forEach(e => {
    const row = el("div", "qentry");
    const when = new Date(e.quarantined_at * 1000).toLocaleString();
    row.innerHTML = `
      <div class="ico"><svg viewBox="0 0 24 24"><rect x="4" y="5" width="16" height="16" rx="2"/><path d="M4 9h16M9 3v4m6-4v4"/></svg></div>
      <div class="meta">
        <b>${e.threat_name}</b>
        <div class="path" title="${e.original_path}">${e.original_path}</div>
        <div class="when">${when}</div>
      </div>
      <div class="threat-actions"></div>`;
    const actions = row.querySelector(".threat-actions");
    const restore = el("button", "btn outline", "Restore");
    restore.onclick = async () => {
      try {
        await invoke("restore_quarantine", { id: e.id });
        toast("Restored", "ok"); loadQuarantine(); refreshQuarantineBadge();
      } catch (err) { toast("Couldn't restore: " + err, "err"); }
    };
    const del = el("button", "btn danger", "Delete");
    del.onclick = async () => {
      try {
        await invoke("delete_quarantine", { id: e.id });
        toast("Deleted", "ok"); loadQuarantine(); refreshQuarantineBadge();
      } catch (err) { toast("Couldn't delete: " + err, "err"); }
    };
    actions.append(restore, del);
    list.appendChild(row);
  });
}

async function refreshQuarantineBadge() {
  try {
    const entries = await invoke("list_quarantine");
    const badge = $("#qBadge");
    badge.textContent = entries.length;
    badge.hidden = entries.length === 0;
    $("#statQ").textContent = entries.length;
  } catch {}
}

init();
