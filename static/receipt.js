(async function () {
  const { api, esc, blockedCard, alertBox, skeleton, rupees, fmtDate } = NITM;
  const box = document.getElementById("receipt");
  box.innerHTML = `<div class="card receipt">${skeleton(6)}</div>`;
  const p = new URLSearchParams(location.search);
  const r = await api(`/api/fees/receipt?userId=${encodeURIComponent(p.get("userId") || "")}&challan=${encodeURIComponent(p.get("challan") || "")}`);
  if (r.blocked) { box.innerHTML = blockedCard(r.data); return; }
  if (!r.ok) { box.innerHTML = alertBox("error", esc(r.data.error || "Could not load the receipt.")); return; }
  const d = r.data;
  box.innerHTML = `
    <article class="card receipt rise" aria-labelledby="rc-title">
      <div class="receipt-head">
        <img src="/static/crest.svg" width="44" height="48" alt="">
        <div><h1 id="rc-title" style="font-size:20px;margin:0">Fee receipt</h1>
          <div class="caption">Northfield Institute of Technology &amp; Management · Accounts section</div></div>
      </div>
      <div class="stamp" aria-hidden="true">PAID</div>
      <dl>
        <dt>Receipt no.</dt><dd class="mono">${esc(d.receipt_no)}</dd>
        <dt>Challan no.</dt><dd class="mono">${esc(d.challan_no)}</dd>
        <dt>Student</dt><dd>${esc(d.name)}</dd>
        <dt>USN</dt><dd>${esc(d.userId)}</dd>
        <dt>Branch</dt><dd>${esc(d.branch_name || d.branch)}</dd>
        <dt>Payment mode</dt><dd>${esc(d.mode)}</dd>
        <dt>Date</dt><dd>${fmtDate(d.date)}</dd>
        <dt>Amount</dt><dd class="amount">${rupees(d.amount)}</dd>
      </dl>
      <p class="caption" style="margin:24px 0 0">Computer-generated receipt. No signature required.</p>
    </article>`;
})();
