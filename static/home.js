(async function () {
  const r = await NITM.api("/api/stats");
  if (!r.ok) return;
  document.querySelectorAll("[data-count]").forEach((el) => NITM.countUp(el, r.data[el.dataset.count] || 0));
})();
