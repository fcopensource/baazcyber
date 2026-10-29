// BaazCyber Antivirus — window logic. Talks to the Rust engine through Tauri commands.
const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;
const dialog = window.__TAURI__.dialog;

const $ = (s) => document.querySelector(s);
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };

// Inject the SVG gradient the ring uses — Veyra mint-teal.
document.body.insertAdjacentHTML("beforeend", `<svg class="defs"><defs><linearGradient id="grad" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#92d3c5"/><stop offset="1" stop-color="#6ec6b5"/></linearGradient></defs></svg>`);

// Build a rotating 3D wireframe globe into every [data-globe] slot.
function buildGlobe(node) {
  const inner = el("div", "globe-inner");
  // Longitude meridians — rings fanned around the vertical axis.
  for (let i = 0; i < 9; i++) {
    const r = el("div", "g-ring" + (i % 3 === 0 ? " lit" : ""));
    r.style.transform = `rotateY(${i * 20}deg)`;
    inner.appendChild(r);
  }
  // Latitude rings — horizontal discs stacked top to bottom, shrinking toward the poles.
  for (let i = -2; i <= 2; i++) {
    const r = el("div", "g-ring" + (i === 0 ? " lit" : ""));
    const s = Math.cos(i * 0.62).toFixed(3);
    r.style.transform = `rotateX(90deg) translateZ(${i * 30}px) scale(${s})`;
    inner.appendChild(r);
  }
  node.appendChild(inner);
  node.appendChild(el("div", "globe-core"));
  node.appendChild(el("div", "globe-sweep"));
}
document.querySelectorAll("[data-globe]").forEach(buildGlobe);

const state = { scanning: false, lastDetections: [] };

// ---- Navigation ----
function show(view) {
  document.querySelectorAll(".view").forEach(v => v.hidden = v.dataset.view !== view);
  document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === view));
  if (view === "quarantine") loadQuarantine();
}
document.querySelectorAll(".nav-item").forEach(n => n.addEventListener("click", () => show(n.dataset.view)));

// ---- Toast ----
let toastTimer;
function toast(msg, kind = "") {
  const t = $("#toast");
  t.textContent = msg; t.className = `toast ${kind}`; t.hidden = false;
  requestAnimationFrame(() => t.classList.add("show"));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.classList.remove("show"); setTimeout(() => t.hidden = true, 300); }, 3200);
}

const SEV_ICON = {
  critical: '<svg viewBox="0 0 24 24"><path d="M12 2 2 20h20z"/><path d="M12 9v5M12 17h.01"/></svg>',
  high: '<svg viewBox="0 0 24 24"><path d="M12 2 2 20h20z"/><path d="M12 9v5M12 17h.01"/></svg>',
  medium: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>',
  low: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg>',
};
const fmtBytes = (n) => n > 1e9 ? (n/1e9).toFixed(1)+" GB" : n > 1e6 ? (n/1e6).toFixed(0)+" MB" : (n/1e3).toFixed(0)+" KB";

// ---- Startup ----
async function init() {
  try {
    const count = await invoke("signature_count");
    $("#statSig").textContent = (count + 2).toLocaleString();
    $("#sigText").textContent = `${(count + 2).toLocaleString()} known threats`;
  } catch {}
  refreshQuarantineBadge();
}

// ---- Scanning ----
let unlisten;
async function runScan(paths, label) {
  if (state.scanning) return;
  state.scanning = true;
  state.lastDetections = [];
  document.body.classList.add("scanning");
  show("scan");
  $("#scanTitle").textContent = label;
  $("#scanPath").textContent = paths.length ? paths.join("  ·  ") : "The usual places malware arrives";
  $("#scanBar").hidden = false;
  $("#runScanBtn").hidden = true;
  $("#pickFolderBtn").hidden = true;
  $("#stopScanBtn").hidden = false;
  $("#results").innerHTML = "";
  $("#resultsBar").hidden = true;
  $("#scanCount").textContent = "0";
  $("#scanThreats").textContent = "0";
  $("#scanFile").textContent = "Starting…";
  setShieldScanning(true);

  unlisten = await listen("scan:progress", (e) => {
    const p = e.payload;
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
  } finally {
    if (unlisten) unlisten();
    state.scanning = false;
    document.body.classList.remove("scanning");
    $("#scanBar").hidden = true;
    $("#runScanBtn").hidden = false;
    $("#pickFolderBtn").hidden = false;
    $("#stopScanBtn").hidden = true;
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
    list.appendChild(el("div", "empty", `<img src="logo-mark.svg" width="56" height="56" alt=""><p>${summary.cancelled ? "Scan stopped." : "No threats found. You're clean."}</p>`));
    setStatus("ok", "You're protected", `Scanned ${summary.files.toLocaleString()} files in ${summary.seconds.toFixed(1)}s. Nothing suspicious.`);
    return;
  }

  summary.detections.forEach(d => list.appendChild(threatRow(d)));
  const bar = $("#resultsBar");
  bar.hidden = false;
  $("#resultsSummary").innerHTML = `<b>${summary.detections.length}</b> threat${summary.detections.length===1?"":"s"} found in ${summary.files.toLocaleString()} files`;
  $("#quarantineAllBtn").hidden = real.length === 0;
  setStatus(real.length ? "threat" : "ok", real.length ? `${real.length} threat${real.length===1?"":"s"} found` : "Test file detected", real.length ? "Review them below and quarantine what you don't trust." : "Only harmless test files were found.");
}

function threatRow(d) {
  const t = d.threat, sev = t.severity;
  const row = el("div", `threat ${sev}`);
  row.innerHTML = `
    <div class="sev">${SEV_ICON[sev]}</div>
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
        row.style.opacity = ".4"; q.disabled = true; q.textContent = "Quarantined";
        toast("Moved to quarantine", "ok");
        refreshQuarantineBadge();
      } catch (err) { toast("Couldn't quarantine: " + err, "err"); }
    };
    actions.appendChild(q);
  } else {
    actions.appendChild(el("span", "muted", "harmless"));
  }
  return row;
}

$("#quarantineAllBtn").onclick = async () => {
  const real = state.lastDetections.filter(d => d.threat && d.threat.kind !== "test");
  let done = 0;
  for (const d of real) {
    try { await invoke("quarantine_file", { path: d.path, sha256: d.sha256, name: d.threat.name, reasons: d.threat.reasons }); done++; } catch {}
  }
  toast(`${done} file${done===1?"":"s"} quarantined`, "ok");
  refreshQuarantineBadge();
  show("quarantine");
};

// ---- Shield status ----
function setStatus(kind, title, sub) {
  $("#statusTitle").textContent = title;
  $("#statusSub").textContent = sub;
  const stage = $(".shield-stage");
  stage.classList.remove("threat");
  if (kind === "threat") stage.classList.add("threat");
  const ring = $("#ringProg");
  ring.style.stroke = kind === "threat" ? "var(--red)" : "url(#grad)";
  ring.style.strokeDashoffset = "0";
}
function setShieldScanning(on) {
  const stage = $(".shield-stage");
  stage.classList.toggle("scanning", on);
  $("#sweep").hidden = !on;
  if (on) { $("#ringProg").style.strokeDashoffset = "157"; }
}

// ---- Scan buttons ----
$("#quickScanBtn").onclick = () => runScan([], "Quick Scan");
$("#runScanBtn").onclick = () => runScan([], "Quick Scan");
$("#fullScanBtn").onclick = async () => {
  const home = await pickDriveRoot();
  runScan(home ? [home] : [], home ? "Full Scan" : "Quick Scan");
};
async function chooseFolder() {
  const picked = await dialog.open({ directory: true, multiple: false, title: "Choose a folder to scan" });
  if (picked) runScan([picked], "Custom Scan");
}
$("#customScanBtn").onclick = chooseFolder;
$("#pickFolderBtn").onclick = chooseFolder;
$("#stopScanBtn").onclick = () => invoke("cancel_scan");
async function pickDriveRoot() {
  // "Full scan" on the user's whole home folder.
  const picked = await dialog.open({ directory: true, multiple: false, title: "Choose what a full scan covers (for example your user folder)" });
  return picked || null;
}

// ---- Quarantine ----
async function loadQuarantine() {
  const list = $("#qList");
  let entries = [];
  try { entries = await invoke("list_quarantine"); } catch {}
  list.innerHTML = "";
  $("#statQ").textContent = entries.length;
  if (!entries.length) {
    list.appendChild(el("div", "empty", `<img src="logo-mark.svg" width="56" height="56" alt=""><p>Quarantine is empty.</p>`));
    return;
  }
  entries.forEach(e => {
    const row = el("div", "qentry");
    const when = new Date(e.quarantined_at * 1000).toLocaleString();
    row.innerHTML = `
      <div class="ico"><svg viewBox="0 0 24 24"><rect x="4" y="5" width="16" height="16" rx="2"/><path d="M4 9h16M9 3v4m6-4v4"/></svg></div>
      <div class="meta"><b>${e.threat_name}</b><div class="path" title="${e.original_path}">${e.original_path}</div><div class="when">${when}</div></div>
      <div class="threat-actions"></div>`;
    const actions = row.querySelector(".threat-actions");
    const restore = el("button", "btn ghost", "Restore");
    restore.onclick = async () => {
      try { await invoke("restore_quarantine", { id: e.id }); toast("Restored", "ok"); loadQuarantine(); refreshQuarantineBadge(); }
      catch (err) { toast("Couldn't restore: " + err, "err"); }
    };
    const del = el("button", "btn danger", "Delete");
    del.onclick = async () => {
      try { await invoke("delete_quarantine", { id: e.id }); toast("Deleted", "ok"); loadQuarantine(); refreshQuarantineBadge(); }
      catch (err) { toast("Couldn't delete: " + err, "err"); }
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
