/* Kavach extension guard: loaded only on pages where a student is logged in.

   A web page cannot list the browser's installed extensions. What it CAN see is
   an extension touching the page, and those are exactly the extensions that can
   read a student's results, fees or ID card off the screen. Footprints:

     1. files loaded from chrome-extension://, moz-extension://, ... URLs
     2. custom elements (<grammarly-extension>, <bit-...>): the portal defines none
     3. elements added outside <main>, or scripts / styles / iframes the portal never ships
     4. marker attributes that extensions put on <html> or <body> (data-gr-ext-installed, ...)
     5. the page's own fetch / XMLHttpRequest replaced by an extension (data interception)

   Each footprint becomes a stable key (ext:<id>, tag:<name>, ...) so the same
   extension looks the same on every page.

   Baseline rule: extensions already active when the student logs in are allowed
   for that session (and listed on the dashboard). A footprint the session has not
   seen before (an extension switched on or clicked into the page after login)
   ends the session. The server keeps the baseline and makes the decision.

   Browser features such as Chrome's "Save password?" bubble are not part of the
   page, so they are never seen here. */
(function () {
  "use strict";

  const INITIAL_MS = 2500;                            // footprints in this window after load = "already there"
  const HEARTBEAT_MS = 4000;                          // re-check with the server (agent ON/OFF, held footprints)
  const EXT_URL = /^(?:chrome|moz|safari-web|ms-browser|edge)?-?extension:\/\/([^/]+)/i;
  const KNOWN_IDS = {                                 // Chrome Web Store ids -> names (for the messages only)
    hhddpjpacfjaakjioinajgmhlbhfchao: "Shield Wallet",
    hnafhkjheookmokbkpnfpmemlppjdgoi: "Allow Right-Click",
    nebnhfamliijlghikdgcigoebonmoibm: "Leo Wallet",
    nkbihfbeogaeaoehlefnkodbefgpgknn: "MetaMask",
    kbfnbcaeplbcioakkpcpgfkobkghlhen: "Grammarly",
    hdokiejnpimakedhajhdlcegeplioahd: "LastPass",
    nngceckbapebfimnlniiiahkandclblb: "Bitwarden",
    aeblfdkhhhdcdjpifhhbdiojplfjncoa: "1Password",
    eimadpbcbfnmbkopoojfekhnkhdbieeh: "Dark Reader",
    oldceeleldhonbafppcapldpdifcinji: "LanguageTool",
    bmnlcjabgnpnenekpadlanbbkooimhnj: "Honey",
    aapbdbdomjkkjkaonfhkkikfgjllcleb: "Google Translate",
  };
  const KNOWN = [                                     // footprint text -> name
    [/grammarly|data-gr-|gr-ext/i, "Grammarly"],
    [/darkreader/i, "Dark Reader"],
    [/lastpass|data-lp-|data-lastpass/i, "LastPass"],
    [/bitwarden|tag:bit-|data-bw/i, "Bitwarden"],
    [/1password|com-1password|data-op-/i, "1Password"],
    [/languagetool|data-lt-|lt-toolbar/i, "LanguageTool"],
    [/honey/i, "Honey"],
    [/metamask/i, "MetaMask"],
    [/cz-shortcut-listen|colorzilla/i, "ColorZilla"],
  ];
  const MARKER_ATTR = /^(data-(gr|new-gr|lt|lp|lastpass|bw|op|darkreader|dashlane|honey|wxt|extension)|cz-shortcut-listen)/i;
  const OK_BODY = new Set(["A", "DIV", "HEADER", "MAIN", "FOOTER", "SCRIPT"]);
  const OK_HEAD = new Set(["META", "TITLE", "LINK", "SCRIPT"]);
  const FOREIGN_TAGS = new Set(["STYLE", "IFRAME", "OBJECT", "EMBED"]);

  const seen = new Map();                             // key -> {key, text, name}
  let pending = [];                                   // live-phase items not yet reported
  let phase = "initial", done = false, timer = null;
  let agentOn = true, retry = [];                     // agent state from the server; footprints held while OFF
  const _fetch = window.fetch, _toString = Function.prototype.toString;
  const _preventDefault = Event.prototype.preventDefault;   // kept so a swapped preventDefault cannot disarm Kavach
  const _own = Object.prototype.hasOwnProperty;

  const stable = (s) => String(s || "").replace(/\d+/g, "").slice(0, 40);

  function nameFor(key, text) {
    const id = key.startsWith("ext:") ? key.slice(4) : null;
    if (id && KNOWN_IDS[id]) return KNOWN_IDS[id];
    for (const [rx, name] of KNOWN) if (rx.test(key + " " + text)) return name;
    if (key.startsWith("tamper:")) return "right-click unblocker (e.g. Allow Right-Click)";
    return id ? `unidentified extension (${id.slice(0, 8)}…)` : null;
  }

  function flag(key, text) {
    if (done || seen.has(key) || seen.size >= 24) return;
    const item = { key, text: text.slice(0, 120), name: nameFor(key, text) };
    seen.set(key, item);
    if (phase === "live") {
      pending.push(item);
      clearTimeout(timer);
      timer = setTimeout(() => send("live", pending.splice(0)), 250);
    }
  }

  function short(el) {
    let s = el.tagName.toLowerCase();
    if (el.id) s += "#" + stable(el.id);
    else if (typeof el.className === "string" && el.className.trim()) s += "." + stable(el.className.trim().split(/\s+/)[0]);
    return s;
  }

  const urlOf = (el) => (el.getAttribute && (el.getAttribute("src") || el.getAttribute("href"))) || "";

  function extFromUrl(url) {
    const m = EXT_URL.exec(url || "");
    if (m) flag("ext:" + m[1].toLowerCase(), "extension file " + url.slice(0, 100));
    return !!m;
  }

  // ------------------------------------------------------------ checks on one element
  function inspect(el) {
    if (!el || el.nodeType !== 1 || done) return;
    const tag = el.tagName, url = urlOf(el);
    const isExt = extFromUrl(url);
    if (tag.includes("-")) flag("tag:" + tag.toLowerCase(), "custom element <" + tag.toLowerCase() + ">");
    for (const a of el.attributes || []) {
      if (MARKER_ATTR.test(a.name)) flag("attr:" + a.name.toLowerCase(), `marker attribute ${a.name} on <${tag.toLowerCase()}>`);
    }
    if (tag === "SCRIPT" && url && !isExt && !url.startsWith("/static/")) {
      let origin = url;
      try { origin = new URL(url, location.href).origin; } catch (e) { /* keep raw */ }
      flag("script:" + origin, "foreign script " + url.slice(0, 100));
    }
    if (FOREIGN_TAGS.has(tag)) flag("dom:" + short(el), "injected <" + short(el) + ">");
  }

  function inMain(el) {
    const main = document.getElementById("main");
    return main && main.contains(el);
  }

  function inspectPlacement(el) {
    if (el.nodeType !== 1 || inMain(el)) return;
    const p = el.parentElement;
    let where = null;
    if (p === document.documentElement && el.tagName !== "HEAD" && el.tagName !== "BODY") where = "html";
    else if (p === document.head && !OK_HEAD.has(el.tagName)) where = "head";
    else if (p === document.body && !OK_BODY.has(el.tagName)) where = "body";
    if (where) flag(`dom:${where}>${short(el)}`, `element added to <${where}>: <${short(el)}>`);
  }

  function scanTree(root) {
    if (root.nodeType !== 1) return;
    inspect(root);
    root.querySelectorAll("*").forEach(inspect);
  }

  // ------------------------------------------------------------ 1. what is already there
  scanTree(document.documentElement);
  for (const parent of [document.documentElement, document.head, document.body]) {
    for (const el of parent.children) inspectPlacement(el);
  }

  // ------------------------------------------------------------ 2. anything added later
  new MutationObserver((records) => {
    for (const r of records) {
      if (r.type === "attributes") {
        if (MARKER_ATTR.test(r.attributeName)) inspect(r.target);
        else extFromUrl(urlOf(r.target));
        continue;
      }
      for (const n of r.addedNodes) {
        if (n.nodeType !== 1) continue;
        inspectPlacement(n);
        if (!inMain(n) || n.tagName.includes("-") || FOREIGN_TAGS.has(n.tagName)) scanTree(n);
        else n.querySelectorAll("*").forEach((c) => { if (c.tagName.includes("-") || EXT_URL.test(urlOf(c))) inspect(c); });
      }
    }
    if (records.some((r) => r.type === "childList" && r.addedNodes.length)) protectLinks();
    checkTamper();                                  // unblockers swap built-ins and touch the page together
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true,
    attributeFilter: ["src", "href", "data-gr-ext-installed", "data-new-gr-c-s-check-loaded", "data-lt-installed",
      "data-darkreader-mode", "data-darkreader-scheme", "data-lastpass-root", "cz-shortcut-listen", "data-wxt-integrated"] });

  // ------------------------------------------------------------ 3. files fetched from an extension
  try {
    const see = (list) => list.forEach((e) => extFromUrl(e.name));
    see(performance.getEntriesByType("resource"));
    new PerformanceObserver((l) => see(l.getEntries())).observe({ type: "resource", buffered: true });
  } catch (e) { /* older browsers: the DOM checks still run */ }

  // ------------------------------------------------------------ 4. hooked network functions
  const native = (fn) => typeof fn === "function" && /\[native code\]/.test(_toString.call(fn));
  // Unblockers (Allow Right-Click and similar) redefine these built-ins so that pages,
  // and Kavach, can no longer cancel right-click, copy or text selection. Natively
  // preventDefault / returnValue live only on Event.prototype (never on MouseEvent or
  // ClipboardEvent), and the others are the browser's own functions, so a hit is tampering.
  // "tamper:" footprints are enforced even if they were present at login.
  function checkTamper() {
    const has = (o, p) => { try { return _own.call(o, p); } catch (e) { return false; } };
    if (has(MouseEvent.prototype, "preventDefault") || has(MouseEvent.prototype, "returnValue"))
      flag("tamper:mouse.preventDefault", "MouseEvent.preventDefault replaced: right-click blocking disabled");
    if (Event.prototype.preventDefault !== _preventDefault)
      flag("tamper:event.preventDefault", "Event.preventDefault replaced: page protections disabled");
    if (typeof ClipboardEvent !== "undefined" && has(ClipboardEvent.prototype, "preventDefault"))
      flag("tamper:clipboard.preventDefault", "ClipboardEvent.preventDefault replaced: copy/paste blocking disabled");
    const sel = Object.getOwnPropertyDescriptor(Selection.prototype, "removeAllRanges");   // natively an own method
    if (!sel || sel.get || !native(sel.value))
      flag("tamper:selection", "Selection.removeAllRanges replaced: text-selection protection disabled");
    const al = Object.getOwnPropertyDescriptor(window, "alert");
    if (al && (al.get || !native(al.value))) flag("tamper:alert", "window.alert replaced");
    if (!native(EventTarget.prototype.addEventListener))
      flag("tamper:addEventListener", "EventTarget.addEventListener replaced: page listeners can be skipped");
  }

  function checkHooks() {
    checkTamper();
    if (Function.prototype.toString !== _toString) flag("hook:toString", "Function.toString replaced (hides other hooks)");
    if (!native(window.fetch)) flag("hook:fetch", "window.fetch replaced");
    if (!native(XMLHttpRequest.prototype.open)) flag("hook:xhr.open", "XMLHttpRequest.open replaced");
    if (!native(XMLHttpRequest.prototype.send)) flag("hook:xhr.send", "XMLHttpRequest.send replaced");
  }
  checkHooks();
  setInterval(checkHooks, 3000);

  // ------------------------------------------------------------ report
  // initial: everything seen so far (the server keeps it as the session's baseline,
  //          or compares it with the baseline on later pages)
  // live:    footprints that appeared after that, sent as they happen
  setTimeout(() => {
    checkHooks();
    phase = "live";
    send("initial", [...seen.values()]);
  }, INITIAL_MS);

  // Heartbeat: keeps the agent state fresh (for the right-click rule) and re-sends
  // footprints the server could not act on while the agent was OFF, so switching the
  // agent back ON catches them without a refresh or a new login.
  setInterval(() => { if (phase === "live") send(retry.length ? "live" : "ping", retry.splice(0)); }, HEARTBEAT_MS);

  // ------------------------------------------------------------ right-click (context menu) extensions
  // Extensions in the right-click menu read the selected text inside the browser and never
  // touch the page, so they cannot be seen. While the agent is ON, the menu is switched off
  // on logged-in pages (mouse, Shift+F10 and the menu key all raise this event).
  let lastMenuReport = 0, lastMenuSeen = 0;
  window.addEventListener("contextmenu", (e) => {
    lastMenuSeen = Date.now();
    if (!agentOn || done) return;
    _preventDefault.call(e);                          // the original: works even if the page's copy was swapped
    checkTamper();
    if (!e.defaultPrevented) flag("tamper:contextmenu", "Right-click menu forced open despite Kavach");
    toast("Right-click is turned off by Kavach on this page: right-click extensions can read what you select.");
    if (Date.now() - lastMenuReport > 30000) { lastMenuReport = Date.now(); send("contextmenu", []); }
  }, true);

  // A right-click whose menu event never reached Kavach: something swallowed it before us.
  // (Windows fires the menu on button release, macOS/Linux on press, so check both ways.)
  window.addEventListener("mouseup", (e) => {
    if (e.button !== 2 || !agentOn || done) return;
    const t0 = Date.now();
    setTimeout(() => {
      if (lastMenuSeen < t0 - 1500) flag("tamper:contextmenu-skipped", "Right-click menu opened without passing through Kavach");
    }, 400);
  }, true);

  function toast(text) {
    let t = document.getElementById("kavach-toast");
    if (!t) {
      t = document.createElement("div");
      t.id = "kavach-toast";
      t.setAttribute("role", "status");
      t.style.cssText = "position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:9999;max-width:min(92vw,520px);" +
        "background:#0F3D2E;color:#fff;padding:12px 16px;border-radius:10px;font:14px/1.4 system-ui,sans-serif;" +
        "box-shadow:0 8px 24px rgba(0,0,0,.25);border-left:4px solid #C99A2E";
      document.body.appendChild(t);
    }
    t.textContent = text;
    t.hidden = false;
    clearTimeout(t._timer);
    t._timer = setTimeout(() => { t.hidden = true; }, 3500);
  }

  // ------------------------------------------------------------ protected downloads
  // Links marked data-kavach-download ("Generate receipt" on Fees, "Download
  // acknowledgement" on Acknowledgement). While the agent is ON the real download URL
  // is never in the page: each link points to a random dead end (/kavach/scrambled/<id>) and
  // the real URL lives only in this closure. A click fetches a one-time ticket and
  // downloads with it. Dragging the link out hands over the dead end, and the drag is
  // reported to the dashboard. With the agent OFF the plain link is restored.
  const REAL = new Map();                             // scrambled id -> {href, file, kind, ref, userId}
  const REF_PARAM = { receipt: "challan", acknowledgement: "sem" };   // which URL parameter names the document
  const NOUN = { receipt: "receipt", acknowledgement: "acknowledgement" };
  const newId = () => (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36)).replace(/-/g, "");
  let dragging = null;

  function scramble(a, real) {
    const id = newId();
    REAL.set(id, real);
    a.dataset.kv = id;
    a.setAttribute("href", "/kavach/scrambled/" + id);
    a.removeAttribute("download");
    a.title = "Protected by Kavach: this link only works here";
  }

  function protectLinks() {
    document.querySelectorAll("a[data-kavach-download]").forEach((a) => {
      if (agentOn && !a.dataset.kv && !done) {
        const href = a.getAttribute("href") || "";
        const u = new URL(href, location.href);
        const kind = a.dataset.kavachDownload;
        scramble(a, { href, kind, file: a.getAttribute("download") || kind + ".pdf",
                      ref: u.searchParams.get(REF_PARAM[kind] || "") || "", userId: u.searchParams.get("userId") || "" });
      } else if (!agentOn && a.dataset.kv) {
        const real = REAL.get(a.dataset.kv);
        delete a.dataset.kv;
        a.removeAttribute("title");
        if (real) { a.setAttribute("href", real.href); a.setAttribute("download", real.file); }
      }
    });
  }
  protectLinks();

  const linkOf = (e) => e.target && e.target.closest ? e.target.closest("a[data-kavach-download]") : null;

  window.addEventListener("click", async (e) => {
    const a = linkOf(e);
    if (!a || !a.dataset.kv) return;                  // agent OFF: the browser downloads the plain link itself
    _preventDefault.call(e);
    const real = REAL.get(a.dataset.kv);
    if (!real) return;
    const noun = NOUN[real.kind] || "file";
    toast(`Preparing your ${noun}…`);
    try {
      const t = await (await _fetch.call(window, "/kavach/ticket", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ kind: real.kind, userId: real.userId, ref: real.ref }),
      })).json().catch(() => ({}));
      const res = await _fetch.call(window, real.href, {
        credentials: "same-origin", headers: t.ticket ? { "X-Kavach-Ticket": t.ticket } : {},
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        toast(d.reason || d.error || `Could not download the ${noun}.`);
        return;
      }
      const url = URL.createObjectURL(await res.blob());
      const tmp = document.createElement("a");
      tmp.href = url;
      tmp.download = real.file;
      tmp.click();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      toast(`${noun.charAt(0).toUpperCase() + noun.slice(1)} downloaded.`);
    } catch (err) {
      toast("Could not download the file.");
    }
  }, true);

  function reportLink(event, id, real, where) {
    _fetch.call(window, "/kavach/link", {
      method: "POST", credentials: "same-origin", keepalive: true,
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ event, id, kind: real.kind, ref: real.ref, where, path: location.pathname }),
    }).catch(() => {});
  }

  window.addEventListener("dragstart", (e) => {
    const a = linkOf(e);
    if (!a || !a.dataset.kv || !agentOn) return;
    const id = a.dataset.kv, real = REAL.get(id);
    const dead = location.origin + "/kavach/scrambled/" + id;
    try {
      e.dataTransfer.clearData();                     // nothing of the real link leaves the page
      e.dataTransfer.setData("text/uri-list", dead);
      e.dataTransfer.setData("text/plain", dead);
    } catch (err) { /* the href itself is already the dead end */ }
    dragging = { a, id, real };
    reportLink("drag", id, real, "");
  }, true);

  window.addEventListener("dragend", (e) => {
    if (!dragging) return;
    const { a, id, real } = dragging;
    dragging = null;
    const accepted = e.dataTransfer && e.dataTransfer.dropEffect && e.dataTransfer.dropEffect !== "none";
    const outside = e.clientX <= 0 || e.clientY <= 0 || e.clientX >= innerWidth || e.clientY >= innerHeight;
    if (accepted || outside) {
      reportLink("drop", id, real, accepted ? "outside the portal (another tab, window, website or app took it)"
                                            : "outside the portal window");
      toast("Kavach scrambled this download link: it will not download anywhere else.");
    }
    scramble(a, real);                                // fresh dead end for the next drag; the dragged one stays dead
  }, true);

  async function send(kind, items) {
    if (done || (kind === "live" && !items.length)) return;
    let reply = {};
    try {
      const res = await _fetch.call(window, "/kavach/extension", {
        method: "POST", credentials: "same-origin", keepalive: true,
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ phase: kind, items, path: location.pathname }),
      });
      reply = await res.json().catch(() => ({}));
    } catch (e) { retry.push(...items); return; /* server unreachable: decide nothing, try again later */ }
    agentOn = reply.agent !== false;
    protectLinks();
    if (reply.action === "none") retry.push(...items);  // agent OFF: hold them until it is switched back ON
    if (reply.action !== "logout") return;
    done = true;
    try { sessionStorage.setItem("kavach_ext", JSON.stringify(reply.names || [])); } catch (e) { /* private mode */ }
    location.replace("/student/login?kavach=extension");
  }
})();
