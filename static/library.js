(async function () {
  const { api, esc, blockedCard, alertBox, skeleton, emptyState, fmtDate } = NITM;
  const mine = document.getElementById("mine"), board = document.getElementById("board");
  if (window.matchMedia("(max-width: 860px)").matches) document.getElementById("libgrid").style.gridTemplateColumns = "1fr";
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const due = (iso) => {
    const days = Math.round((new Date(iso + "T00:00:00") - today) / 864e5);
    if (days < 0) return `<span class="pill pill-danger">Overdue ${-days}d</span>`;
    if (days <= 7) return `<span class="pill pill-warn">Due in ${days}d</span>`;
    return `<span class="pill pill-ok">${fmtDate(iso)}</span>`;
  };

  mine.innerHTML = skeleton(2);
  board.innerHTML = `<div class="card">${skeleton(6)}</div>`;

  const [m, b] = await Promise.all([api("/api/library/mine"), api("/api/library/borrowers?limit=20")]);

  if (m.status === 401) mine.innerHTML = `<p class="muted">Sign in to see the books you've borrowed.</p><a class="btn btn-sm" href="/student/login?next=/library">Student login</a>`;
  else if (m.blocked) mine.innerHTML = blockedCard(m.data);
  else if (!m.data.rows?.length) mine.innerHTML = emptyState("No books on loan", "Anything you borrow shows up here.");
  else mine.innerHTML = m.data.rows.map((x) => `<div class="device-row"><span>${esc(x.book)}</span>${due(x.due)}</div>`).join("");

  if (b.blocked) { board.innerHTML = blockedCard(b.data); return; }
  if (!b.ok) { board.innerHTML = alertBox("error", esc(b.data.error || "Could not load the borrower board.")); return; }
  if (!b.data.rows.length) { board.innerHTML = emptyState("Nothing on loan", ""); return; }
  // Only name, book and due date are shown. (The API sends more: that's WEAK SPOT #2.)
  board.innerHTML = `<div class="table-wrap"><table>
    <thead><tr><th scope="col">Student</th><th scope="col">Book</th><th scope="col">Due</th></tr></thead>
    <tbody>${b.data.rows.map((x) => `<tr><td>${esc(x.student_name)}</td><td>${esc(x.book)}</td><td>${due(x.due)}</td></tr>`).join("")}</tbody>
  </table></div>`;
})();
