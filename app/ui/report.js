// BaazCyber Antivirus: PDF security report (built offline with the bundled jsPDF)
const NAVY = [11, 18, 38], INK = [30, 41, 59], MUTED = [100, 116, 139], LINE = [226, 232, 240], SOFT = [244, 247, 251];
const GREEN = [16, 185, 129], RED = [225, 29, 72], AMBER = [217, 119, 6], BLUE = [37, 99, 235];
const SEV = { critical: { c: RED, label: "CRITICAL" }, high: { c: [244, 63, 94], label: "HIGH" }, medium: { c: AMBER, label: "MEDIUM" }, low: { c: GREEN, label: "LOW" } };

// The built-in PDF fonts only cover Latin-1; replace anything else so it can't break the layout.
const clean = (s) => String(s ?? "").replace(/[–—]/g, "-").replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/…/g, "...").replace(/[^\x20-\xFF\n]/g, "?");
const fmtBytes = (n) => n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1e3 ? `${(n / 1e3).toFixed(0)} KB` : `${n} bytes`;
const fmtTime = (s) => s >= 60 ? `${Math.floor(s / 60)} min ${Math.round(s % 60)} s` : `${s.toFixed(1)} s`;

export function buildReport(r) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const W = 210, H = 297, M = 16, CW = W - 2 * M;
  let y = 0;

  const text = (s, x, yy, o = {}) => {
    doc.setFont("helvetica", o.bold ? "bold" : "normal");
    doc.setFontSize(o.size || 10);
    doc.setTextColor(...(o.color || INK));
    doc.text(clean(s), x, yy, o.align ? { align: o.align } : undefined);
  };
  const wrap = (s, width, size) => { doc.setFontSize(size); return doc.splitTextToSize(clean(s), width); };
  const ensure = (need) => { if (y + need > H - 22) { doc.addPage(); y = M + 4; } };
  const heading = (s) => {
    ensure(16);
    y += 4;
    doc.setFillColor(...GREEN); doc.rect(M, y - 3.6, 1.4, 5, "F");
    text(s, M + 4, y, { bold: true, size: 12.5, color: NAVY });
    y += 7;
  };

  const real = r.detections.filter(d => d.threat.kind !== "test");
  const active = real.filter(d => !d.done);
  const quarantined = real.filter(d => d.done);
  const tests = r.detections.filter(d => d.threat.kind === "test");
  const status = active.length ? { c: RED, t: `${active.length} threat${active.length === 1 ? "" : "s"} need${active.length === 1 ? "s" : ""} attention`, s: "Move the files listed below to quarantine, then run the scan again." }
    : quarantined.length ? { c: GREEN, t: "Threats found and quarantined", s: `All ${quarantined.length} threat${quarantined.length === 1 ? " was" : "s were"} moved to quarantine, where they cannot run.` }
    : { c: GREEN, t: r.cancelled ? "No threats in the files checked" : "Clean: no threats found", s: r.cancelled ? "The scan was stopped before it finished. Run it again to check everything." : "Every file in the scanned locations was checked and nothing suspicious was found." };

  // ── Header band ──
  doc.setFillColor(...NAVY); doc.rect(0, 0, W, 42, "F");
  doc.setFillColor(...GREEN); doc.rect(0, 42, W, 1.2, "F");
  // Shield mark
  doc.setFillColor(...GREEN);
  doc.lines([[8, 3], [0, 7], [-1, 6, -5, 9, -8, 11], [-3, -2, -7, -5, -8, -11], [0, -7]], M + 8, 11, [1, 1], "F", true);
  doc.setDrawColor(255, 255, 255); doc.setLineWidth(1.1);
  doc.lines([[2.4, 2.4], [4.6, -5]], M + 5, 20.5);
  text("BaazCyber Antivirus", M + 22, 20, { bold: true, size: 17, color: [255, 255, 255] });
  text("Security Scan Report", M + 22, 27, { size: 10.5, color: [52, 245, 176] });
  const when = new Date(r.at);
  text(when.toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" }), W - M, 19, { size: 10, color: [255, 255, 255], align: "right" });
  text(when.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }), W - M, 25, { size: 9, color: [160, 174, 204], align: "right" });
  text(`Report ${r.id}`, W - M, 31, { size: 8, color: [160, 174, 204], align: "right" });
  y = 54;

  // ── Verdict card with score ──
  doc.setFillColor(...SOFT); doc.setDrawColor(...LINE); doc.setLineWidth(.3);
  doc.roundedRect(M, y, CW, 34, 3, 3, "FD");
  doc.setFillColor(...status.c); doc.rect(M, y, 2.2, 34, "F");
  text(status.t, M + 8, y + 12, { bold: true, size: 15, color: status.c });
  wrap(status.s, CW - 58, 9.5).slice(0, 3).forEach((l, i) => text(l, M + 8, y + 19 + i * 4.6, { size: 9.5, color: MUTED }));
  const cx = W - M - 20, cy = y + 15, R = 10;
  doc.setDrawColor(...LINE); doc.setLineWidth(2.6); doc.circle(cx, cy, R, "S");
  doc.setLineCap("round");
  const sc = r.score >= 80 ? GREEN : r.score >= 50 ? AMBER : RED;
  doc.setDrawColor(...sc);
  // Arc for the score, drawn as short segments from the top, clockwise.
  const steps = Math.round(120 * r.score / 100);
  for (let i = 0; i < steps; i++) {
    const a1 = -Math.PI / 2 + (i / 120) * 2 * Math.PI, a2 = -Math.PI / 2 + ((i + 1) / 120) * 2 * Math.PI;
    doc.line(cx + R * Math.cos(a1), cy + R * Math.sin(a1), cx + R * Math.cos(a2), cy + R * Math.sin(a2));
  }
  doc.setLineCap("butt");
  text(String(r.score), cx, cy + 2.4, { bold: true, size: 15, color: NAVY, align: "center" });
  text("SECURITY SCORE", cx, cy + 15.5, { size: 6.5, color: MUTED, align: "center" });
  y += 44;

  // ── Summary ──
  heading("Scan summary");
  const rows = [
    ["Scan type", r.label + (r.cancelled ? " (stopped early)" : "")],
    ["Date", when.toLocaleString()],
    ["Duration", fmtTime(r.seconds)],
    ["Files scanned", r.files.toLocaleString()],
    ["Data scanned", fmtBytes(r.bytes || 0)],
    ["Threats found", `${real.length}${tests.length ? ` (+${tests.length} harmless test file${tests.length === 1 ? "" : "s"})` : ""}`],
    ["Quarantined", String(quarantined.length)],
    ["Engine", `Signatures (${r.signatures.toLocaleString()} known) + heuristics`],
  ];
  const colW = CW / 2;
  rows.forEach(([k, v], i) => {
    const col = i % 2, x = M + col * colW;
    if (col === 0 && i > 0) y += 9;
    ensure(10);
    text(k.toUpperCase(), x, y, { size: 7, color: MUTED, bold: true });
    text(wrap(v, colW - 6, 10)[0], x, y + 4.6, { size: 10, color: INK, bold: true });
  });
  y += 13;

  // ── Locations ──
  heading("Locations scanned");
  (r.paths.length ? r.paths : ["(default locations)"]).slice(0, 12).forEach(p => {
    wrap(p, CW - 6, 9).forEach((l, i) => { ensure(5); if (i === 0) { doc.setFillColor(...BLUE); doc.circle(M + 1.2, y - 1.1, .7, "F"); } text(l, M + 4, y, { size: 9, color: INK }); y += 4.6; });
  });
  if (r.paths.length > 12) { text(`...and ${r.paths.length - 12} more`, M + 4, y, { size: 9, color: MUTED }); y += 4.6; }
  y += 3;

  // ── Findings ──
  heading("Findings");
  if (!r.detections.length) {
    doc.setFillColor(236, 253, 245); doc.roundedRect(M, y - 2, CW, 12, 2, 2, "F");
    text("No threats were found in the scanned files.", M + 5, y + 5.5, { size: 10, color: [4, 120, 87], bold: true });
    y += 16;
  } else {
    const cols = [{ w: 23, t: "SEVERITY" }, { w: 55, t: "THREAT" }, { w: CW - 23 - 55 - 24, t: "FILE AND REASON" }, { w: 24, t: "STATUS" }];
    const head = () => {
      doc.setFillColor(...NAVY); doc.rect(M, y, CW, 8, "F");
      let x = M + 3;
      cols.forEach(c => { text(c.t, x, y + 5.4, { size: 7.5, bold: true, color: [255, 255, 255] }); x += c.w; });
      y += 8;
    };
    head();
    r.detections.forEach((d, idx) => {
      const sev = SEV[d.threat.severity] || SEV.medium;
      // Break long detection names at their dots, not mid-word.
      const nameL = wrap(d.threat.name.replace(/\./g, ". "), cols[1].w - 4, 9).map(l => l.replace(/\. /g, ".").trim());
      const pathL = wrap(d.path.replace(/[\\/]/g, "$& "), cols[2].w - 4, 8).map(l => l.replace(/([\\/]) /g, "$1").trim());
      const whyL = wrap(d.threat.reasons[0] || "", cols[2].w - 4, 8.5);
      const h = Math.max(nameL.length * 4.4, (pathL.length + whyL.length) * 3.9 + 1.5, 8) + 5;
      if (y + h > H - 22) { doc.addPage(); y = M + 4; head(); }
      if (idx % 2) { doc.setFillColor(...SOFT); doc.rect(M, y, CW, h, "F"); }
      doc.setDrawColor(...LINE); doc.setLineWidth(.2); doc.line(M, y + h, M + CW, y + h);
      let x = M + 3;
      doc.setFillColor(...sev.c); doc.roundedRect(x, y + 2.6, 18, 5, 1.2, 1.2, "F");
      text(d.threat.kind === "test" ? "TEST" : sev.label, x + 9, y + 6, { size: 6.5, bold: true, color: [255, 255, 255], align: "center" });
      x += cols[0].w;
      nameL.forEach((l, i) => text(l, x, y + 6 + i * 4.4, { size: 9, bold: true }));
      x += cols[1].w;
      let ly = y + 5.6;
      pathL.forEach(l => { text(l, x, ly, { size: 8, color: MUTED }); ly += 3.9; });
      whyL.forEach(l => { text(l, x, ly + .8, { size: 8.5 }); ly += 3.9; });
      x += cols[2].w;
      const st = d.threat.kind === "test" ? ["Harmless", GREEN] : d.done ? ["Quarantined", GREEN] : ["Active", RED];
      text(st[0], x, y + 6, { size: 8.5, bold: true, color: st[1] });
      y += h;
    });
    y += 6;
  }

  // ── Recommendations ──
  heading("Recommendations");
  const recs = [];
  if (active.length) recs.push(`Quarantine the ${active.length} active threat${active.length === 1 ? "" : "s"} listed above from the BaazCyber Scan page, then scan again.`);
  if (active.some(d => /Credential|Mimikatz|Lsass|Keylogger/i.test(d.threat.name))) recs.push("A password-stealing threat was found. Change the passwords you use on this computer from a different, clean device.");
  if (active.some(d => /Ransom|DisableDefender/i.test(d.threat.name))) recs.push("Ransomware behaviour was found. Disconnect from shared drives and back up important files to an external drive.");
  if (r.cancelled) recs.push("This scan was stopped early. Run it again and let it finish to check every file.");
  if (r.label !== "Full Scan") recs.push("Run a Full Scan regularly to check every file on your system drive, not just the common hiding places.");
  recs.push("Keep BaazCyber updated so it has the newest detection rules.");
  recs.push("Only open attachments and downloads you expect, and check them with File Scan first.");
  recs.forEach(s => {
    const ls = wrap(s, CW - 6, 9.5);
    ensure(ls.length * 4.8 + 2);
    doc.setFillColor(...GREEN); doc.circle(M + 1.2, y - 1.2, .8, "F");
    ls.forEach(l => { text(l, M + 4, y, { size: 9.5 }); y += 4.8; });
    y += 1.2;
  });

  // ── Method ──
  heading("How BaazCyber checks files");
  [
    ["Fingerprints", "Each file's SHA-256 fingerprint is compared with known malware. A match is certain."],
    ["Signatures", "Byte patterns of specific threats, including the industry EICAR test file."],
    ["Heuristics", "Programs, scripts, web pages and file names are checked for the techniques malware uses, such as injecting code, stealing passwords, disabling security or disguising file types. Each sign scores points, and a file is reported only when the evidence adds up."],
  ].forEach(([k, v]) => {
    const ls = wrap(v, CW - 32, 9);
    ensure(ls.length * 4.5 + 3);
    text(k, M, y, { size: 9, bold: true, color: NAVY });
    ls.forEach(l => { text(l, M + 30, y, { size: 9, color: INK }); y += 4.5; });
    y += 2;
  });

  // ── Footer on every page ──
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setDrawColor(...LINE); doc.setLineWidth(.3); doc.line(M, H - 14, W - M, H - 14);
    text("BaazCyber Antivirus  |  A FlightCoders company  |  Files were scanned on this computer and never uploaded.", M, H - 9, { size: 7.5, color: MUTED });
    text(`Page ${i} of ${pages}`, W - M, H - 9, { size: 7.5, color: MUTED, align: "right" });
  }
  doc.setProperties({ title: `BaazCyber Security Report ${r.id}`, subject: "Security scan report", author: "BaazCyber Antivirus", creator: "BaazCyber Antivirus" });
  return new Uint8Array(doc.output("arraybuffer"));
}
