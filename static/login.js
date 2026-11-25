(function () {
  const { api, alertBox, blockedCard, esc } = NITM;
  const $ = (id) => document.getElementById(id);
  const msg = $("msg"), f1 = $("step1"), f2 = $("step2"), fo = $("otp");
  const params = new URLSearchParams(location.search);
  const next = params.get("next") && params.get("next").startsWith("/") ? params.get("next") : "/results";
  let pausedRoll = null;

  if (params.get("kavach") === "session_ended") {
    msg.innerHTML = alertBox("warn", "<strong>Kavach ended your session.</strong> It was used from another device, sat idle too long, or came from an untrusted device on a new network. Please sign in again.");
  }

  document.querySelectorAll(".reveal").forEach((b) => b.addEventListener("click", () => {
    const input = document.getElementById(b.getAttribute("aria-controls"));
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    b.textContent = show ? "Hide" : "Show";
    b.setAttribute("aria-pressed", String(show));
  }));

  function setStep(n) {
    $("st1").className = n === 1 ? "active" : "done";
    $("st2").className = n === 2 ? "active" : "";
    f1.hidden = n !== 1; f2.hidden = n !== 2; fo.hidden = true;
    (n === 1 ? $("roll") : $("idcard")).focus();
  }

  function busy(form, on) {
    const b = form.querySelector("button[type=submit]");
    b.disabled = on;
    b.dataset.label = b.dataset.label || b.textContent;
    b.textContent = on ? "Checking…" : b.dataset.label;
  }

  function handleFailure(r) {
    if (r.blocked && r.data.otp_required) {
      pausedRoll = r.data.roll;
      msg.innerHTML = blockedCard(r.data);
      f1.hidden = f2.hidden = true; fo.hidden = false; $("otpcode").focus();
      return;
    }
    if (r.blocked) { msg.innerHTML = blockedCard(r.data); f1.hidden = f2.hidden = true; return; }
    const kind = r.status === 423 ? "warn" : "error";
    const lead = r.status === 423 ? "<strong>Account locked.</strong> " : "";
    msg.innerHTML = alertBox(kind, lead + esc(r.data.error || "Something went wrong."));
  }

  f1.addEventListener("submit", async (e) => {
    e.preventDefault();
    const roll = $("roll").value.trim(), dob = $("dob").value.trim();
    if (!roll || !dob) { msg.innerHTML = alertBox("error", "Enter your USN and password."); return; }
    busy(f1, true);
    const r = await api("/api/auth/step1", { json: { roll, dob } });
    busy(f1, false);
    if (!r.ok) return handleFailure(r);
    msg.innerHTML = "";
    $("hello").innerHTML = `Hi <strong>${esc(r.data.name_hint)}</strong>, one more step.`;
    setStep(2);
  });

  f2.addEventListener("submit", async (e) => {
    e.preventDefault();
    busy(f2, true);
    const r = await api("/api/auth/step2", { json: { id_card: $("idcard").value.trim() } });
    busy(f2, false);
    if (!r.ok) { $("idcard").select(); return handleFailure(r); }
    msg.innerHTML = alertBox("ok", `Welcome back, ${esc(r.data.name)}. Taking you in…`);
    setTimeout(() => (location.href = next), 500);
  });

  $("back").addEventListener("click", () => { msg.innerHTML = ""; setStep(1); });

  fo.addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = await api("/kavach/otp", { json: { roll: pausedRoll, otp: $("otpcode").value.trim() } });
    if (!r.ok) { msg.innerHTML = alertBox("error", esc(r.data.error)); return; }
    msg.innerHTML = alertBox("ok", "Verified. Sign in again to continue.");
    setStep(1);
  });
})();
