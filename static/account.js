(function () {
  const { api, esc, alertBox, skeleton, emptyState, refreshBell } = NITM;
  const $ = (id) => document.getElementById(id);
  const ago = (ts) => {
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : new Date(ts * 1000).toLocaleString("en-IN");
  };
  const KIND = {
    new_device: ["New device", "pill-warn"], lockout_shield: ["Attack blocked", "pill-danger"],
    hijack: ["Session hijack", "pill-danger"], frozen: ["Account paused", "pill-danger"],
  };

  async function load() {
    $("alerts").innerHTML = skeleton(3);
    const r = await api("/api/me/alerts");
    if (!r.ok) { $("alerts").innerHTML = alertBox("error", esc(r.data.error || "Could not load alerts.")); return; }
    const d = r.data;
    if (!d.agent_on) $("acct-msg").innerHTML = alertBox("warn", "<strong>Kavach protection is switched off.</strong> Sign-in alerts and device checks are paused.");
    else $("acct-msg").innerHTML = "";

    $("alerts").innerHTML = d.alerts.length ? d.alerts.map((a) => {
      const [label, cls] = KIND[a.kind] || ["Notice", "pill-info"];
      const acts = a.action ? `<div class="alert-actions">
          ${a.action.type === "new_device" && a.action.device ? `<button class="btn btn-sm" data-do="trust">Yes, it was me: trust this device</button>` : ""}
          <button class="btn btn-ghost btn-sm" data-do="notme">This wasn't me: log out everywhere</button></div>` : "";
      return `<div class="alert-item ${a.read ? "" : "unread"}">
        <span class="pill ${cls}" style="align-self:start">${label}</span>
        <div><h3 style="margin:0">${esc(a.title)}</h3><p>${esc(a.body)}</p>
        <div class="caption" style="margin-bottom:8px">${ago(a.ts)}</div>${acts}</div></div>`;
    }).join("") : emptyState("No alerts", "Kavach tells you here if someone tries your account or signs in from a new device.");

    const t = d.this_device;
    $("thisdev").innerHTML = `<div class="device-row"><span>Device <span class="mono">${esc(t.id)}</span></span>
        ${t.trusted ? '<span class="pill pill-ok">Trusted</span>' : '<span class="pill pill-warn">Untrusted: short sessions</span>'}</div>
      ${t.trusted ? "" : `<p class="caption" style="margin:8px 0 12px">Untrusted devices are signed out after a few idle minutes or when the network changes, so a login forgotten on a friend's phone expires on its own.</p>
      <button class="btn btn-sm" data-do="trust">This is my own device: trust it</button>`}`;

    $("sessions").innerHTML = d.sessions.map((s) => `<div class="device-row">
        <span><span class="mono">${esc(s.device)}</span> · ${esc(s.ip)}<br><span class="caption">signed in ${ago(s.created)} · active ${ago(s.last_seen)}</span></span>
        ${s.current ? '<span class="pill pill-info">This session</span>' : s.trusted ? '<span class="pill pill-ok">Trusted</span>' : '<span class="pill pill-warn">Untrusted</span>'}
      </div>`).join("") || emptyState("No sessions", "");

    if (d.unread) { await api("/api/me/alerts/read", { method: "POST" }); refreshBell(); }
  }

  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-do]");
    if (!b) return;
    b.disabled = true;
    if (b.dataset.do === "trust") {
      await api("/api/me/trust-device", { method: "POST" });
      $("acct-msg").innerHTML = alertBox("ok", "This device is now trusted. Normal session length applies.");
    } else if (b.dataset.do === "notme") {
      const r = await api("/api/me/not-me", { method: "POST" });
      $("acct-msg").innerHTML = alertBox("ok", `Done. Ended ${r.data.ended ?? 0} other session(s) and told the IT team. Consider changing your password.`);
    }
    load();
  });

  $("logout-all").addEventListener("click", async () => {
    await api("/api/auth/logout-all", { method: "POST" });
    location.href = "/student/login";
  });

  load();
})();
