(function () {
  const { api, esc, blockedCard, alertBox, skeleton, emptyState } = NITM;
  const out = document.getElementById("out"), q = document.getElementById("q");
  out.innerHTML = emptyState("Search for an applicant", "Results show the applicant's branch and current status.");
  const pill = { Admitted: "pill-ok", Shortlisted: "pill-info", Waitlisted: "pill-warn", Applied: "pill-gold" };

  document.getElementById("search").addEventListener("submit", async (e) => {
    e.preventDefault();
    const term = q.value.trim();
    if (!term) return;
    out.innerHTML = `<div class="card">${skeleton(4)}</div>`;
    const r = await api("/api/admissions/search?q=" + encodeURIComponent(term));
    if (r.blocked) { out.innerHTML = blockedCard(r.data); return; }
    if (!r.ok) { out.innerHTML = alertBox("error", esc(r.data.error || "Search failed.") + (r.data.detail ? `<br><span class="mono">${esc(r.data.detail)}</span>` : "")); return; }
    if (!r.data.rows.length) { out.innerHTML = emptyState("No applicants found", `Nobody matches "${term}". Try a first name or surname.`); return; }
    const rows = r.data.rows.slice(0, 200);
    out.innerHTML = `<p class="caption">${r.data.count.toLocaleString("en-IN")} match${r.data.count === 1 ? "" : "es"}${r.data.count > 200 ? " (showing 200)" : ""}</p>
      <div class="table-wrap rise"><table>
      <thead><tr><th scope="col">Applicant</th><th scope="col">Branch</th><th scope="col">Status</th></tr></thead>
      <tbody>${rows.map((x) => `<tr><td>${esc(x.name)}</td><td>${esc(x.branch)}</td><td><span class="pill ${pill[x.status] || "pill-info"}">${esc(x.status)}</span></td></tr>`).join("")}</tbody>
      </table></div>`;
  });
})();
