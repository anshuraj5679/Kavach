/* Kavach dashboard: polls /api/kavach/state every second and renders it. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const hms = (ts) => new Date(ts * 1000).toLocaleTimeString("en-GB", { hour12: false });
  const ago = (ts) => {
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    return s < 5 ? "just now" : s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : hms(ts);
  };
  const LEVEL_LABEL = { critical: "critical", leak: "leak", block: "blocked", warn: "warning", protect: "protected", info: "info" };
  const EMPTY_ICON = '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5Z"/><path d="m9 12 2 2 4-4"/></svg>';
  const empty = (title, html) => `<div class="empty">${EMPTY_ICON}<strong>${title}</strong>${html}</div>`;

  let state = null, first = true, ledgerFilter = "all";
  const shownStats = { inspected: 0, blocked: 0, leaked: 0, protected: 0 };
  const seenEvents = new Map(), seenIncidents = new Set(), seenLeaks = new Set();
  let incSig = "", ledgerSig = "", notifSig = "", blockSig = "";
  let failures = 0;

  // ------------------------------------------------------------------ polling
  async function poll() {
    try {
      const r = await fetch("/api/kavach/state", { cache: "no-store" });
      if (!r.ok) throw new Error(r.status);
      state = await r.json();
      failures = 0;
      setConn(true);
      render(state);
    } catch (e) {
      if (++failures >= 2) setConn(false);
    } finally {
      setTimeout(poll, 1000);
    }
  }

  function setConn(ok) {
    const chip = $("chip-conn");
    chip.classList.toggle("down", !ok);
    chip.lastElementChild.textContent = ok ? "Live" : "Reconnecting…";
  }

  function render(s) {
    document.body.classList.remove("loading");
    renderSwitch(s.enabled);
    $("chip-llm").textContent = "Reports: " + s.llm;
    $("chip-anom").textContent = "Anomaly model: " + s.anomaly.split(" ")[0];
    $("thresholds").textContent = `block after ${s.thresholds.foreign} foreign records, ${s.thresholds.logins} failed logins, or ${s.thresholds.rows}+ rows in one reply, within ${s.thresholds.window / 60} min`;
    renderStats(s.stats);
    renderFeed(s.events);
    renderIncidents(s.incidents);
    renderLedger(s.leaks);
    renderNotifs(s.notifications);
    renderBlocks(s.blocks, s.frozen);
    if (first && /^#INC-\d+$/.test(location.hash)) openReport(location.hash.slice(1), null);   // deep link to a report
    first = false;
  }

  // ------------------------------------------------------------------ switch
  let pendingToggle = false;
  function renderSwitch(on) {
    if (pendingToggle) return;
    const sw = $("agent-switch");
    sw.setAttribute("aria-checked", String(on));
    sw.setAttribute("aria-label", on ? "Agent is on. Switch it off" : "Agent is off. Switch it on");
    $("switch-text").textContent = on ? "ON" : "OFF";
    document.body.classList.toggle("agent-off", !on);
    $("off-banner").hidden = on;
  }
  $("agent-switch").addEventListener("click", async () => {
    const next = $("agent-switch").getAttribute("aria-checked") !== "true";
    pendingToggle = false;
    renderSwitch(next);                      // optimistic: the colour flips immediately
    pendingToggle = true;
    try {
      await fetch("/api/kavach/toggle", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: next }) });
    } finally {
      pendingToggle = false;
    }
  });

  // ------------------------------------------------------------------ reset (two-click confirm)
  let resetTimer = null;
  $("reset").addEventListener("click", async () => {
    const b = $("reset");
    if (!b.classList.contains("confirm")) {
      b.classList.add("confirm");
      b.textContent = "Click again to reset";
      resetTimer = setTimeout(() => { b.classList.remove("confirm"); b.textContent = "Reset demo"; }, 3000);
      return;
    }
    clearTimeout(resetTimer);
    b.classList.remove("confirm");
    b.textContent = "Resetting…";
    await fetch("/api/kavach/reset", { method: "POST" });
    seenEvents.clear(); seenIncidents.clear(); seenLeaks.clear();
    $("feed").innerHTML = "";
    incSig = ledgerSig = notifSig = blockSig = "";
    b.textContent = "Reset demo";
  });

  // ------------------------------------------------------------------ stats
  function renderStats(stats) {
    for (const key of Object.keys(shownStats)) {
      const to = stats[key] || 0, from = shownStats[key];
      if (to === from && !first) continue;
      shownStats[key] = to;
      const el = document.querySelector(`[data-stat="${key}"]`);
      countUp(el, from, to);
      if (to > from && !first && !reduceMotion) {
        const tile = el.closest(".tile");
        tile.classList.remove("bump"); void tile.offsetWidth; tile.classList.add("bump");
      }
    }
  }
  function countUp(el, from, to) {
    if (reduceMotion || from === to) { el.textContent = to.toLocaleString("en-IN"); return; }
    const t0 = performance.now(), ms = 700;
    const step = (t) => {
      const p = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(from + (to - from) * e).toLocaleString("en-IN");
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  // ------------------------------------------------------------------ feed
  function renderFeed(events) {
    const feed = $("feed");
    if (first) feed.innerHTML = "";
    if (!events.length) {
      if (!feed.querySelector(".empty")) {
        feed.innerHTML = `<li style="display:block;padding:0">${empty("No events yet", state.enabled
          ? "<p>Browse the portal or run <code>python attacks/simulate.py all</code></p>"
          : "<p>The agent is off, so nothing is being watched.</p>")}</li>`;
      }
      return;
    }
    feed.querySelector(".empty")?.parentElement.remove();
    for (const e of events) {
      const known = seenEvents.get(e.id);
      if (known) {
        if (known.count !== e.count) {
          known.count = e.count;
          const c = known.el.querySelector(".count");
          c.textContent = "×" + e.count; c.hidden = false;
          known.el.querySelector("time").textContent = hms(e.ts);
        }
        continue;
      }
      const li = document.createElement("li");
      li.className = `lvl-${e.level}` + (first ? "" : " new");
      li.innerHTML = `<time datetime="${new Date(e.ts * 1000).toISOString()}">${hms(e.ts)}</time>
        <span class="pill lvl-pill-${e.level}">${LEVEL_LABEL[e.level] || e.level}</span>
        <span class="msg">${esc(e.message)}<span class="count" ${e.count > 1 ? "" : "hidden"}>×${e.count}</span>${e.incident_id ? `<button type="button" class="inc-link" data-inc="${esc(e.incident_id)}">${esc(e.incident_id)}</button>` : ""}</span>`;
      feed.prepend(li);
      seenEvents.set(e.id, { el: li, count: e.count });
    }
    while (feed.children.length > 120) {
      const last = feed.lastElementChild;
      for (const [id, v] of seenEvents) if (v.el === last) seenEvents.delete(id);
      last.remove();
    }
    $("feed-count").textContent = `${events.length} recent`;
  }

  // ------------------------------------------------------------------ incidents
  function renderIncidents(incs) {
    const sig = incs.map((i) => i.id + ":" + i.version).join("|");
    const box = $("incidents");
    if (sig === incSig) {           // only refresh the relative times
      box.querySelectorAll("[data-ts]").forEach((t) => (t.textContent = ago(+t.dataset.ts)));
      return;
    }
    incSig = sig;
    if (!incs.length) {
      box.innerHTML = empty("No incidents yet", "<p>When Kavach flags something, it appears here with a risk score and an AI-written report.</p>");
      return;
    }
    box.innerHTML = incs.map((i) => {
      const isNew = !seenIncidents.has(i.id) && !first;
      seenIncidents.add(i.id);
      return `<button type="button" class="inc${isNew ? " new" : ""}" data-sev="${i.severity}" data-inc="${esc(i.id)}"
          aria-label="${esc(i.severity)} incident ${esc(i.id)}: ${esc(i.title)}. Open report">
        <div class="inc-top"><span class="pill sev-${i.severity}">${i.severity}</span><span class="inc-id">${esc(i.id)}</span>
          <span class="inc-time" data-ts="${i.last_seen}">${ago(i.last_seen)}</span></div>
        <div class="inc-title">${esc(i.title)}</div>
        <div class="inc-action">${esc(i.action)}</div>
        <div class="inc-stats">
          <span class="leak"><b>${i.records_leaked}</b> leaked</span>
          <span class="prot"><b>${i.records_protected.toLocaleString("en-IN")}</b> protected</span>
          <span class="risk">risk ${i.risk}<span class="risk-bar" aria-hidden="true"><span style="width:${i.risk}%"></span></span></span>
        </div></button>`;
    }).join("");
  }

  // ------------------------------------------------------------------ ledger
  function renderLedger(rows) {
    const shown = rows.filter((r) => ledgerFilter === "all" || r.outcome === ledgerFilter);
    const sig = ledgerFilter + ":" + shown.map((r) => r.id).join(",");
    if (sig === ledgerSig) return;
    ledgerSig = sig;
    const body = $("ledger");
    if (!shown.length) {
      body.innerHTML = `<tr><td colspan="8">${empty(ledgerFilter === "all" ? "Nothing has leaked or been masked yet" : `No ${ledgerFilter} records`,
        "<p>Every record that leaves the server for the wrong person gets a row here.</p>")}</td></tr>`;
      return;
    }
    body.innerHTML = shown.slice(0, 150).map((r) => {
      const isNew = !seenLeaks.has(r.id) && !first;
      seenLeaks.add(r.id);
      return `<tr class="${isNew ? "new" : ""}">
        <td class="mono">${hms(r.ts)}</td>
        <td><span class="pill out-${r.outcome}">${r.outcome}</span></td>
        <td><span class="mono">${esc(r.record_id)}</span><span class="who">${esc(r.owner_name || "")}</span></td>
        <td>${r.fields.map((f) => `<span class="field-chip">${esc(f)}</span>`).join("")}</td>
        <td>${esc(r.to_whom)}</td>
        <td class="mono">${esc(r.ip)}</td>
        <td class="mono">${esc(r.endpoint)}</td>
        <td><button type="button" class="link-btn" data-inc="${esc(r.incident_id)}">${esc(r.incident_id)}</button></td></tr>`;
    }).join("");
  }
  document.querySelectorAll(".seg-btn").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".seg-btn").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    ledgerFilter = b.dataset.filter;
    if (state) renderLedger(state.leaks);
  }));

  // ------------------------------------------------------------------ alerts + blocks
  const KIND_PILL = { lockout_shield: ["sev-high", "lockout shield"], new_device: ["sev-medium", "new device"], hijack: ["sev-critical", "hijack"],
    frozen: ["sev-critical", "frozen"], block: ["sev-high", "block"], not_me: ["sev-high", "not me"] };
  function renderNotifs(list) {
    const sig = list.map((n) => n.id).join(",");
    if (sig === notifSig) return;
    notifSig = sig;
    $("notifs").innerHTML = list.length ? list.map((n) => {
      const [cls, label] = KIND_PILL[n.kind] || ["lvl-pill-info", n.kind];
      const to = n.audience === "student" ? `to student ${esc(n.roll)}` : "to IT head";
      return `<li><div class="n-top"><span class="pill ${cls}">${esc(label)}</span><span>${to}</span><time>${hms(n.ts)}</time></div>
        <strong>${esc(n.title)}</strong><p>${esc(n.body)}</p></li>`;
    }).join("") : `<li style="border:0">${empty("No alerts sent", "<p>Students are told when someone tries their account or signs in from a new device.</p>")}</li>`;
  }
  function renderBlocks(blocks, frozen) {
    const sig = blocks.map((b) => b.key).join(",") + "/" + frozen.map((f) => f.roll).join(",");
    if (sig === blockSig) return;
    blockSig = sig;
    const items = [
      ...blocks.map((b) => `<li><div class="n-top"><span class="pill sev-high">${b.device === "*" ? "whole IP" : "IP + device"}</span>
        <span class="mono">${esc(b.ip)}${b.device === "*" ? "" : " · " + esc(b.device.slice(0, 6)) + "…"}</span>
        <time>until ${hms(b.until)}</time></div><p>${esc(b.reason)} · <button type="button" class="link-btn" data-inc="${esc(b.incident_id)}">${esc(b.incident_id)}</button></p></li>`),
      ...frozen.map((f) => `<li><div class="n-top"><span class="pill sev-critical">account frozen</span><span class="mono">USN ${esc(f.roll)}</span>
        <time>until ${hms(f.until)}</time></div><p>${esc(f.reason)} · OTP re-verification required</p></li>`),
    ];
    $("blocks").innerHTML = items.join("") || `<li style="border:0">${empty("Nothing blocked", "<p>Blocked attackers and frozen accounts show here.</p>")}</li>`;
  }

  // ------------------------------------------------------------------ report drawer
  const dlg = $("report");
  let lastOpener = null, currentReport = null;
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-inc]");
    if (t && t.dataset.inc && t.dataset.inc !== "null") openReport(t.dataset.inc, t);
  });
  $("rep-close").addEventListener("click", () => dlg.close());
  dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
  dlg.addEventListener("close", () => lastOpener?.focus?.());

  async function openReport(id, opener) {
    lastOpener = opener;
    const inc = state?.incidents.find((i) => i.id === id);
    $("rep-kicker").innerHTML = `${esc(id)} ${inc ? `<span class="pill sev-${inc.severity}">${inc.severity}</span>` : ""}`;
    $("rep-title").textContent = inc ? inc.title : "AI report";
    $("rep-facts").innerHTML = inc ? [
      ["IP", inc.actor.ip], ["device", inc.actor.device], ["account", inc.actor.roll || "anonymous"],
      ["risk", inc.risk + "/100"], ["leaked", inc.records_leaked], ["protected", inc.records_protected.toLocaleString("en-IN")],
    ].map(([k, v]) => `<span class="fact"><span>${k}</span>${esc(v)}</span>`).join("") : "";
    $("pane-admin").innerHTML = '<div aria-busy="true"><div class="skel" style="width:50%"></div><div class="skel"></div><div class="skel" style="width:80%"></div><div class="skel" style="width:65%"></div><p style="color:var(--muted);padding:0 24px">Writing the report…</p></div>';
    $("pane-notice").innerHTML = "";
    $("rep-by").textContent = "";
    selectTab("admin");
    if (!dlg.open) dlg.showModal();
    try {
      const r = await fetch(`/api/kavach/incidents/${encodeURIComponent(id)}/report`);
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || r.status);
      currentReport = d;
      $("pane-admin").innerHTML = md(d.admin_report);
      $("pane-notice").innerHTML = d.student_notice
        ? `<div class="notice-letter">${esc(d.student_notice)}</div>`
        : empty("No student notice needed", "<p>No records left the server in this incident, so there is nobody to notify.</p>");
      const by = d.written_by.startsWith("llm") ? "LLM" : "template";
      const model = by === "LLM" ? ` <span class="mono">${esc(d.written_by.replace(/^llm · /, ""))}</span>` : " (offline)";
      $("rep-by").innerHTML = `<span class="writer">written by: <b>${by}</b>${model} · report v${d.version}</span>`;
    } catch (err) {
      $("pane-admin").innerHTML = empty("Couldn't load the report", `<p>${esc(err.message)}</p>`);
    }
  }

  function selectTab(which) {
    for (const t of ["admin", "notice"]) {
      const on = t === which;
      $("tab-" + t).setAttribute("aria-selected", String(on));
      $("tab-" + t).tabIndex = on ? 0 : -1;
      $("pane-" + t).hidden = !on;
    }
  }
  $("tab-admin").addEventListener("click", () => selectTab("admin"));
  $("tab-notice").addEventListener("click", () => selectTab("notice"));
  document.querySelector(".tabs").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const next = $("tab-admin").getAttribute("aria-selected") === "true" ? "notice" : "admin";
    selectTab(next); $("tab-" + next).focus();
  });
  $("rep-copy").addEventListener("click", async () => {
    if (!currentReport) return;
    const onNotice = $("tab-notice").getAttribute("aria-selected") === "true";
    const text = onNotice ? currentReport.student_notice || "" : currentReport.admin_report;
    try { await navigator.clipboard.writeText(text); $("rep-copy").textContent = "Copied"; }
    catch { $("rep-copy").textContent = "Copy failed"; }
    setTimeout(() => ($("rep-copy").textContent = "Copy"), 1500);
  });

  // ------------------------------------------------------------------ tiny markdown (escaped first)
  function md(src) {
    const out = [];
    const parts = String(src || "").split(/```[a-z]*\n?/);
    parts.forEach((chunk, i) => {
      if (i % 2 === 1) { out.push(`<pre><code>${esc(chunk.replace(/\n$/, ""))}</code></pre>`); return; }
      let list = false;
      for (const raw of chunk.split("\n")) {
        const line = raw.trimEnd();
        const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>");
        if (/^\s*[-*] /.test(line)) { if (!list) { out.push("<ul>"); list = true; } out.push(`<li>${inline(line.replace(/^\s*[-*] /, ""))}</li>`); continue; }
        if (list) { out.push("</ul>"); list = false; }
        if (/^### /.test(line)) out.push(`<h3>${inline(line.slice(4))}</h3>`);
        else if (/^## /.test(line)) out.push(`<h2>${inline(line.slice(3))}</h2>`);
        else if (/^# /.test(line)) out.push(`<h2>${inline(line.slice(2))}</h2>`);
        else if (line.trim()) out.push(`<p>${inline(line)}</p>`);
      }
      if (list) out.push("</ul>");
    });
    return out.join("");
  }

  // first paint: skeleton rows while the first poll is in flight
  $("feed").innerHTML = '<li style="display:block;padding:0"><div class="skel"></div><div class="skel" style="width:70%"></div><div class="skel" style="width:85%"></div></li>';
  $("incidents").innerHTML = '<div class="skel"></div><div class="skel" style="width:60%"></div>';
  $("ledger").innerHTML = '<tr><td colspan="8"><div class="skel"></div></td></tr>';
  poll();
})();
