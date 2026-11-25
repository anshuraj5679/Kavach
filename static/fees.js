(async function () {
  const { api, esc, blockedCard, alertBox, skeleton, emptyState, rupees, fmtDate } = NITM;
  const box = document.getElementById("fees");
  box.innerHTML = `<div class="card">${skeleton(4)}</div>`;
  const r = await api("/api/fees");
  if (r.blocked) { box.innerHTML = blockedCard(r.data); return; }
  if (!r.ok) { box.innerHTML = alertBox("error", esc(r.data.error || "Could not load fees.")); return; }
  if (!r.data.rows.length) { box.innerHTML = emptyState("No challans yet", "Paid challans appear here."); return; }
  const total = r.data.rows.reduce((a, x) => a + x.amount, 0);
  box.innerHTML = `
    <div class="stat-row rise" style="margin-bottom:16px">
      <div class="stat"><div class="stat-num">${rupees(total)}</div><div class="stat-label">Paid this academic year</div></div>
      <div class="stat"><div class="stat-num">${r.data.rows.length}</div><div class="stat-label">Challans</div></div>
      <div class="stat"><div class="stat-num"><span class="pill pill-ok" style="font-size:14px">No dues</span></div><div class="stat-label">Status</div></div>
    </div>
    <div class="table-wrap rise rise-2"><table>
      <thead><tr><th scope="col">Challan</th><th scope="col">Date</th><th scope="col">Mode</th><th scope="col" class="num">Amount</th><th scope="col"><span class="sr-only">Receipt</span></th></tr></thead>
      <tbody>${r.data.rows.map((x) => `<tr>
        <td class="mono">${esc(x.challan_no)}</td><td>${fmtDate(x.date)}</td><td>${esc(x.mode)}</td>
        <td class="num">${rupees(x.amount)}</td>
        <td style="text-align:right"><a class="btn btn-ghost btn-sm" data-kavach-download="receipt" href="/api/fees/receipt/download?userId=${encodeURIComponent(r.data.roll)}&challan=${encodeURIComponent(x.challan_no)}" download="receipt-${esc(x.challan_no)}.pdf">Generate receipt</a></td>
      </tr>`).join("")}</tbody></table></div>`;
})();
