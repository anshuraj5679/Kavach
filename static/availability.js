/* Kavach dashboard: "Portal health" panel (availability shield, agent/availability.py).
   Adds itself under the totals tiles; the rest of the dashboard is untouched. */
(function () {
  "use strict";
  const tiles = document.querySelector("section.tiles");
  if (!tiles) return;

  const style = document.createElement("style");
  style.textContent = `
    .avail { margin-top: var(--s4); }
    .avail [hidden] { display: none !important; }
    .avail .panel-head .sub { color: var(--muted); font-size: 13px; }
    .avail .grow { flex: 1; }
    .avail .toggle { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; color: var(--muted); cursor: pointer; }
    .avail .toggle input { width: 16px; height: 16px; accent-color: var(--high); }
    .avail .body { padding: var(--s3) var(--s4) var(--s4); }
    .avail .stats { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: var(--s3); margin-bottom: var(--s3); }
    .avail .stat .label { color: var(--muted); font-size: 12px; }
    .avail .stat .num { font-size: 22px; font-weight: 600; font-variant-numeric: tabular-nums; margin-top: 2px; }
    .avail .stat .hint { color: var(--faint); font-size: 11px; }
    .avail .chart { position: relative; height: 150px; }
    .avail svg { display: block; width: 100%; height: 100%; overflow: visible; }
    .avail .tip { position: absolute; pointer-events: none; background: var(--panel-2); border: 1px solid var(--border-strong);
      border-radius: 8px; padding: 6px 10px; font-size: 12px; white-space: nowrap; box-shadow: var(--shadow); transform: translate(-50%, -110%); }
    .avail .tip[hidden] { display: none; }
    .avail .note { margin: var(--s2) 0 0; color: var(--muted); font-size: 13px; }
    .avail .cap { color: var(--faint); font-size: 12px; margin-top: 4px; }
    @media (max-width: 900px) { .avail .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); } }`;
  document.head.appendChild(style);

  const panel = document.createElement("section");
  panel.className = "panel avail";
  panel.setAttribute("aria-labelledby", "av-title");
  panel.innerHTML = `
    <div class="panel-head">
      <h2 id="av-title">Portal health</h2>
      <span class="pill sev-low" id="av-status">checking</span>
      <span class="pill sev-high" id="av-rush" hidden>Rush mode on</span>
      <span class="sub" id="av-sub">checked every second</span>
      <span class="grow"></span>
      <label class="toggle" title="Make the portal behave like a real campus server: 8 workers and a slower database">
        <input type="checkbox" id="av-server"> Results-day server (demo)</label>
    </div>
    <div class="body">
      <div class="stats">
        <div class="stat"><div class="label">Response time</div><div class="num" id="av-ms">–</div><div class="hint">slowest of probe and pages</div></div>
        <div class="stat"><div class="label">Requests per second</div><div class="num" id="av-rps">–</div><div class="hint">last 5 seconds</div></div>
        <div class="stat"><div class="label">Waiting now</div><div class="num" id="av-wait">–</div><div class="hint">requests in progress</div></div>
        <div class="stat"><div class="label">Results queue</div><div class="num" id="av-queue">–</div><div class="hint">students in line</div></div>
        <div class="stat"><div class="label">Fee lane</div><div class="num" id="av-fee">–</div><div class="hint">average, never queued</div></div>
        <div class="stat"><div class="label">Flood requests refused</div><div class="num" id="av-flood">–</div><div class="hint" id="av-flood-src">since reset</div></div>
      </div>
      <div class="chart" id="av-chart" role="img" aria-label="Portal response time over the last 3 minutes">
        <svg id="av-svg"></svg><div class="tip" id="av-tip" hidden></div>
      </div>
      <div class="cap">Response time, last 3 minutes. Dashed lines: slow and down thresholds. Shaded: rush mode on.</div>
      <p class="note" id="av-note"></p>
    </div>`;
  tiles.insertAdjacentElement("afterend", panel);

  const $ = (id) => document.getElementById(id);
  const fmt = (ms) => (ms >= 1000 ? (ms / 1000).toFixed(1) + " s" : Math.round(ms) + " ms");
  const PILL = { UP: "sev-low", SLOW: "sev-high", DOWN: "sev-critical" };
  let last = null;

  async function refresh() {
    let d;
    try {
      const r = await fetch("/api/kavach/availability", { headers: { Accept: "application/json" } });
      if (!r.ok) return;
      d = await r.json();
    } catch (e) { return; }
    last = d;
    const p = d.points[d.points.length - 1] || {};
    const st = $("av-status");
    st.className = "pill " + (PILL[d.status] || "sev-low");
    st.textContent = d.status === "UP" ? "Up" : d.status === "SLOW" ? "Slow" : "Down";
    $("av-rush").hidden = !d.rush;
    $("av-rush").textContent = d.rush ? `Rush mode on · ${d.rush_for} s` : "";
    $("av-ms").textContent = p.ms != null ? fmt(p.ms) : "–";
    $("av-rps").textContent = p.rps != null ? p.rps : "–";
    $("av-wait").textContent = p.inflight != null ? p.inflight : "–";
    $("av-queue").textContent = d.queue;
    $("av-fee").textContent = d.counters.critical_served ? fmt(d.counters.critical_avg_ms) : "–";
    $("av-flood").textContent = d.counters.flood_refused.toLocaleString("en-IN");
    $("av-flood-src").textContent = d.counters.flood_sources ? `from ${d.counters.flood_sources} source(s)` : "since reset";
    $("av-server").checked = !!d.server_demo;
    $("av-note").textContent = !d.enabled
      ? "Agent is OFF: Kavach is only watching. No flood blocking, no rush mode, no alerts."
      : d.rush ? "Rush mode: fee payment and login keep a reserved lane, results go through a fair queue, library and admissions search are paused."
      : d.server_demo ? `Results-day server is on: the portal behaves like a real campus server (${d.server_workers} workers, slower database).`
      : "";
    draw();
  }

  function draw() {
    const d = last;
    const box = $("av-chart"), svg = $("av-svg");
    const W = box.clientWidth, H = box.clientHeight;
    if (!d || !W) return;
    const pts = d.points;
    const padL = 44, padR = 8, padT = 8, padB = 18;
    const iw = W - padL - padR, ih = H - padT - padB;
    const slow = d.thresholds.slow_ms, down = d.thresholds.down_ms;
    const maxV = Math.max(slow * 1.25, ...pts.map((x) => x.ms));
    const top = maxV <= 1000 ? 1000 : maxV <= 2000 ? 2000 : maxV <= 4000 ? 4000 : Math.ceil(maxV / 2000) * 2000;
    const n = d.thresholds.interval ? Math.round(180 / d.thresholds.interval) : 180;
    const x = (i) => padL + (iw * (i + (n - pts.length))) / Math.max(1, n - 1);
    const y = (v) => padT + ih - (ih * Math.min(v, top)) / top;
    const ticks = [0, top / 2, top];
    let s = "";
    ticks.forEach((t) => {
      s += `<line x1="${padL}" x2="${W - padR}" y1="${y(t)}" y2="${y(t)}" stroke="var(--border)" stroke-width="1"/>`;
      s += `<text x="${padL - 6}" y="${y(t) + 4}" text-anchor="end" font-size="11" fill="var(--faint)">${fmt(t)}</text>`;
    });
    for (let i = 0; i < pts.length; i++) {               // rush-mode shading
      if (pts[i].rush) s += `<rect x="${x(i) - iw / n / 2}" y="${padT}" width="${iw / n + 0.5}" height="${ih}" fill="var(--high-bg)"/>`;
    }
    [[slow, "slow"], [down, "down"]].forEach(([v, label]) => {
      if (v > top) return;
      s += `<line x1="${padL}" x2="${W - padR}" y1="${y(v)}" y2="${y(v)}" stroke="${label === "slow" ? "var(--high)" : "var(--danger)"}" stroke-width="1" stroke-dasharray="4 4" opacity=".7"/>`;
      s += `<text x="${W - padR}" y="${y(v) - 4}" text-anchor="end" font-size="11" fill="var(--muted)">${label}</text>`;
    });
    if (pts.length > 1) {
      const path = pts.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.ms).toFixed(1)}`).join("");
      s += `<path d="${path}" fill="none" stroke="var(--info)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
      const lp = pts[pts.length - 1];
      s += `<circle cx="${x(pts.length - 1)}" cy="${y(lp.ms)}" r="4" fill="var(--info)" stroke="var(--panel)" stroke-width="2"/>`;
    }
    s += `<text x="${padL}" y="${H - 2}" font-size="11" fill="var(--faint)">3 min ago</text>`;
    s += `<text x="${W - padR}" y="${H - 2}" text-anchor="end" font-size="11" fill="var(--faint)">now</text>`;
    s += `<line id="av-cross" x1="0" x2="0" y1="${padT}" y2="${padT + ih}" stroke="var(--muted)" stroke-width="1" visibility="hidden"/>`;
    s += `<rect x="${padL}" y="${padT}" width="${iw}" height="${ih}" fill="transparent" id="av-hit"/>`;
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.innerHTML = s;

    const hit = $("av-hit"), tip = $("av-tip"), cross = $("av-cross");
    hit.addEventListener("mousemove", (e) => {
      const r = svg.getBoundingClientRect();
      const mx = e.clientX - r.left;
      let best = 0, bd = Infinity;
      pts.forEach((p, i) => { const dd = Math.abs(x(i) - mx); if (dd < bd) { bd = dd; best = i; } });
      const p = pts[best];
      if (!p) return;
      cross.setAttribute("x1", x(best)); cross.setAttribute("x2", x(best)); cross.setAttribute("visibility", "visible");
      tip.hidden = false;
      tip.style.left = x(best) + "px";
      tip.style.top = y(p.ms) + "px";
      const t = new Date(p.ts * 1000).toLocaleTimeString("en-IN");
      tip.textContent = `${t} · ${fmt(p.ms)} · ${p.rps}/s · ${p.status.toLowerCase()}${p.rush ? " · rush mode" : ""}`;
    });
    hit.addEventListener("mouseleave", () => { tip.hidden = true; cross.setAttribute("visibility", "hidden"); });
  }

  $("av-server").addEventListener("change", async (e) => {
    await fetch("/api/kavach/demo-capacity", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: e.target.checked }) });
    refresh();
  });
  window.addEventListener("resize", draw);
  refresh();
  setInterval(refresh, 2000);
})();
