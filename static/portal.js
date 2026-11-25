/* Shared helpers for the Northfield portal pages. */
(function () {
  "use strict";
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function api(path, opts = {}) {
    const init = { headers: { Accept: "application/json" }, credentials: "same-origin", ...opts };
    if (opts.json !== undefined) {
      init.method = init.method || "POST";
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.json);
    }
    let res, data = {};
    for (;;) {
      try {
        res = await fetch(path, init);
        data = await res.json().catch(() => ({}));
      } catch (e) {
        showQueue(null);
        return { ok: false, status: 0, data: { error: "Can't reach the portal. Check that the server is running." } };
      }
      // Results-day rush (Kavach availability shield): wait our turn, then try again by ourselves.
      if (res.status === 503 && data.queued) {
        showQueue(data);
        await new Promise((r) => setTimeout(r, data.retry_ms || 1000));
        continue;
      }
      break;
    }
    showQueue(null);
    if (res.status === 401 && data.kavach === "session_ended") {
      location.href = "/student/login?kavach=session_ended";
    }
    return { ok: res.ok, status: res.status, data, blocked: res.status === 403 && data.by === "Kavach" };
  }

  const ICONS = {
    shield: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5Z"/><path d="m9 9 6 6M15 9l-6 6"/></svg>',
    alert: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 8v5M12 16h.01"/></svg>',
    ok: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m8 12 3 3 5-6"/></svg>',
    empty: '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><path d="M3 7h18M5 7l1 13h12l1-13M9 7V4h6v3"/></svg>',
  };

  function blockedCard(data) {
    return `<div class="kavach-block" role="alert">
      <div class="shield">${ICONS.shield}</div>
      <div><span class="tag">Kavach</span>
        <h3>Blocked by Kavach</h3>
        <p>${esc(data.reason || "This request was refused by the portal's security layer.")}</p>
        <div class="meta">incident ${esc(data.incident || "-")} · ${esc(new Date().toLocaleTimeString())}</div>
      </div></div>`;
  }

  function showQueue(d) {
    let el = document.getElementById("kavach-queue");
    if (!d) { if (el) el.remove(); return; }
    if (!el) {
      el = document.createElement("div");
      el.id = "kavach-queue";
      (document.getElementById("main") || document.body).prepend(el);
    }
    el.innerHTML = alertBox("warn", `<strong>Results day is busy.</strong> You're number ${esc(d.position)} in line ` +
      `(about ${esc(d.wait_seconds)} s). This page opens by itself, so there's no need to refresh. Fee payment is not affected.`);
  }

  function alertBox(kind, msg) {
    const icon = kind === "ok" ? ICONS.ok : ICONS.alert;
    return `<div class="alert alert-${kind}" role="${kind === "error" ? "alert" : "status"}">${icon}<div>${msg}</div></div>`;
  }

  function emptyState(title, text) {
    return `<div class="empty">${ICONS.empty}<h3>${esc(title)}</h3><p class="muted">${esc(text || "")}</p></div>`;
  }

  function skeleton(lines = 4) {
    return '<div aria-busy="true" aria-label="Loading"><div class="skeleton lg"></div>' +
      Array.from({ length: lines }, (_, i) => `<div class="skeleton" style="width:${90 - i * 12}%"></div>`).join("") + "</div>";
  }

  function countUp(el, to, ms = 900) {
    if (reduceMotion || !to) { el.textContent = Number(to).toLocaleString("en-IN"); return; }
    const t0 = performance.now();
    const step = (t) => {
      const p = Math.min(1, (t - t0) / ms), eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(to * eased).toLocaleString("en-IN");
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  const rupees = (n) => "₹" + Number(n).toLocaleString("en-IN");
  const fmtDate = (iso) => new Date(iso + (iso.length === 10 ? "T00:00:00" : "")).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });

  async function refreshBell() {
    const bell = document.getElementById("bell");
    if (!bell) return;
    const r = await api("/api/me/alerts");
    if (r.ok && r.data.unread > 0) {
      bell.textContent = r.data.unread;
      bell.hidden = false;
    } else {
      bell.hidden = true;
    }
  }
  refreshBell();
  setInterval(refreshBell, 15000);

  window.NITM = { api, esc, blockedCard, alertBox, emptyState, skeleton, countUp, rupees, fmtDate, ICONS, refreshBell };
})();
