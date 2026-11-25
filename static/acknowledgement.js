(async function () {
  const { api, esc, blockedCard, alertBox, skeleton } = NITM;
  const box = document.getElementById("ack");
  box.innerHTML = `<div class="card">${skeleton(6)}</div>`;
  const r = await api("/api/acknowledgement");
  if (r.blocked) { box.innerHTML = blockedCard(r.data); return; }
  if (!r.ok) { box.innerHTML = alertBox("error", esc(r.data.error || "Could not load your registration.")); return; }
  const d = r.data;
  const href = `/api/acknowledgement/download?userId=${encodeURIComponent(d.userId)}&sem=${encodeURIComponent(d.semester)}`;
  box.innerHTML = `
    <div class="stat-row rise" style="margin-bottom:16px">
      <div class="stat"><div class="stat-num">${esc(d.total)}</div><div class="stat-label">Credits registered</div></div>
      <div class="stat"><div class="stat-num">${esc(d.count)}</div><div class="stat-label">Courses</div></div>
      <div class="stat"><div class="stat-num"><span class="pill pill-ok" style="font-size:14px">Registered</span></div><div class="stat-label">Semester ${esc(d.semester)} · ${esc(d.term)}</div></div>
    </div>
    <article class="card receipt rise rise-2" aria-labelledby="ack-title" style="max-width:none">
      <div class="receipt-head" style="justify-content:space-between;flex-wrap:wrap">
        <div style="display:flex;gap:16px;align-items:center">
          <img src="/static/crest.svg" width="44" height="48" alt="">
          <div><h2 id="ack-title" style="font-size:20px;margin:0">Course Registration Acknowledgement</h2>
            <div class="caption">Northfield Institute of Technology &amp; Management · ${esc(d.term)}</div></div>
        </div>
        <a class="btn btn-sm" data-kavach-download="acknowledgement" href="${href}" download="acknowledgement-sem${esc(d.semester)}-${esc(d.userId)}.pdf">Download acknowledgement</a>
      </div>
      <dl style="margin-bottom:24px">
        <dt>Student</dt><dd>${esc(d.name)}</dd>
        <dt>USN</dt><dd>${esc(d.userId)}</dd>
        <dt>Stream</dt><dd>${esc(d.stream)}</dd>
        <dt>Department</dt><dd>${esc(d.branch_name)}</dd>
        <dt>Semester</dt><dd>Semester ${esc(d.semester)}</dd>
        <dt>Acknowledgement no.</dt><dd class="mono">${esc(d.ack_no)}</dd>
      </dl>
      ${d.groups.map((g) => `
        <h3 style="font-size:15px;margin:20px 0 8px">${esc(g.category)}</h3>
        <div class="table-wrap"><table style="table-layout:fixed;width:100%">
          <colgroup><col style="width:22%"><col><col style="width:14%"></colgroup>
          <thead><tr><th scope="col">Course code</th><th scope="col">Course name</th><th scope="col" class="num">Credits</th></tr></thead>
          <tbody>${g.courses.map((c) => `<tr><td class="mono">${esc(c.code)}</td><td>${esc(c.name)}</td><td class="num">${Number(c.credits).toFixed(2)}</td></tr>`).join("")}</tbody>
        </table></div>`).join("")}
      <p style="margin:20px 0 0"><strong>Total: ${esc(d.total)} credits</strong> across ${esc(d.count)} courses · 0 backlogs</p>
      <p class="caption" style="margin:8px 0 0">The PDF includes the student declaration and signature lines for the student, faculty mentor and head of department.</p>
    </article>`;
})();
