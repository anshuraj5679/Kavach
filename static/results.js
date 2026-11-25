(async function () {
  const { api, esc, blockedCard, alertBox, skeleton } = NITM;
  const box = document.getElementById("results");
  box.innerHTML = `<div class="card">${skeleton(5)}</div>`;
  const roll = new URLSearchParams(location.search).get("roll");
  const r = await api("/api/results" + (roll ? `?roll=${encodeURIComponent(roll)}` : ""));
  if (r.blocked) { box.innerHTML = blockedCard(r.data); return; }
  if (!r.ok) { box.innerHTML = alertBox("error", esc(r.data.error || "Could not load results.")); return; }
  const d = r.data;
  const grade = (m) => (m >= 90 ? "O" : m >= 80 ? "A+" : m >= 70 ? "A" : m >= 60 ? "B+" : m >= 50 ? "B" : m >= 40 ? "C" : "F");
  const sems = d.semesters.map((s, i) => `
    <article class="card sem-card rise" style="animation-delay:${i * 60}ms" aria-labelledby="sem${s.semester}">
      <header><h2 id="sem${s.semester}" style="margin:0;font-size:16px">Semester ${s.semester}</h2>
        <span class="pill pill-info">SGPA ${s.sgpa.toFixed(2)}</span></header>
      <table><thead><tr><th scope="col">Subject</th><th scope="col" class="num">Marks</th><th scope="col">Grade</th></tr></thead>
      <tbody>${Object.entries(s.marks).map(([sub, m]) => `
        <tr><td>${esc(sub)}</td><td class="num">${m}<span class="bar" aria-hidden="true"><span style="width:${m}%"></span></span></td>
        <td><span class="pill ${m >= 40 ? "pill-ok" : "pill-danger"}">${grade(m)}</span></td></tr>`).join("")}
      </tbody></table></article>`).join("");
  box.innerHTML = `
    <section class="card student-banner rise">
      <span class="avatar" aria-hidden="true">${esc(d.name[0])}</span>
      <div><h2 style="margin:0">${esc(d.name)}</h2>
        <div class="muted">USN ${esc(d.roll)} · ${esc(d.branch_name || d.branch)}</div></div>
      <div class="cgpa"><div class="caption">CGPA</div><div class="big">${d.cgpa?.toFixed(2) ?? "-"}</div></div>
    </section>
    <div class="sem-grid">${sems}</div>`;
})();
