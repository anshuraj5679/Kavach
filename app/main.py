"""FastAPI app: the portal, the Kavach dashboard and the agent middleware in one process."""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from agent import actions, availability, detector, explainer, gateway, ledger, linkguard, notify
from agent import config as kconfig
from . import auth, capacity, db, portal

STATIC = Path(__file__).resolve().parent.parent / "static"
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.seed()
    ledger.load()
    watchdog = asyncio.create_task(availability.watchdog())      # portal health, every second
    yield
    watchdog.cancel()


app = FastAPI(title="Kavach demo", docs_url=None, redoc_url=None, lifespan=lifespan)
# Registered first = runs innermost. Order per request:
# flood gate -> gateway -> availability -> capacity -> portal.
app.middleware("http")(capacity.middleware)             # demo "results-day server" (off by default)
app.middleware("http")(availability.middleware)         # floods, results-day rush (agent/availability.py)
app.middleware("http")(gateway.kavach_gateway)          # every request and response passes through Kavach
app.middleware("http")(availability.flood_gate)         # sources already flooding: refused before inspection
capacity.drop_check = availability.flooding             # queued requests of a flooding source are dropped
capacity.priority_check = availability.priority         # logged-in students ahead of anonymous traffic (agent ON)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def static_revalidate(request: Request, call_next):
    """Scripts and styles: the browser may keep a copy but must check it is current before use."""
    resp = await call_next(request)
    if request.url.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-cache"
    return resp
app.include_router(portal.router)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(STATIC / "favicon.svg", media_type="image/svg+xml")


# ====================================================================== dashboard (IT head)
def _local_only(request: Request) -> JSONResponse | None:
    # The dashboard is for the IT head on this machine. Uses the real socket
    # peer, never X-Forwarded-For.
    host = request.client.host if request.client else ""
    if host not in LOCAL_HOSTS:
        return JSONResponse({"error": "Dashboard is available on localhost only."}, status_code=403)
    return None


@app.get("/admin", include_in_schema=False)
def dashboard(request: Request):
    if (err := _local_only(request)):
        return err
    return HTMLResponse(portal.versioned((STATIC / "dashboard.html").read_text(encoding="utf-8")),
                        headers={"Cache-Control": "no-store"})


@app.get("/api/kavach/state")
def kavach_state(request: Request):
    if (err := _local_only(request)):
        return err
    snap = ledger.snapshot()
    snap["notifications"] = notify.recent(20)
    snap["llm"] = explainer.llm_mode()
    snap["anomaly"] = detector.ANOMALY.status
    snap["thresholds"] = {"foreign": kconfig.FOREIGN_RECORD_LIMIT, "rows": kconfig.ROW_SPIKE_LIMIT,
                          "logins": kconfig.FAILED_LOGIN_LIMIT, "window": kconfig.WINDOW_SECONDS}
    return snap


@app.post("/api/kavach/toggle")
async def kavach_toggle(request: Request):
    if (err := _local_only(request)):
        return err
    try:
        body = await request.json()
    except ValueError:
        body = {}
    on = bool(body.get("enabled", not ledger.enabled()))
    ledger.set_enabled(on)
    if on:
        ledger.event("info", "Agent switched ON: every request is inspected", dedupe=False)
    return {"enabled": on}


@app.post("/api/kavach/reset")
def kavach_reset(request: Request):
    if (err := _local_only(request)):
        return err
    ledger.reset()
    detector.reset()
    explainer.clear_cache()
    auth.reset_state()
    linkguard.reset()
    availability.reset()
    ledger.event("info", "Demo reset: ledger, blocks, sessions and portal lockouts cleared", dedupe=False)
    return {"ok": True, "enabled": ledger.enabled()}


@app.get("/api/kavach/availability")
def kavach_availability(request: Request):
    if (err := _local_only(request)):
        return err
    workers, db_ms = capacity.profile()
    return {**availability.snapshot(), "server_demo": capacity.enabled(),
            "server_workers": workers, "server_db_ms": db_ms}


@app.post("/api/kavach/demo-capacity")
async def kavach_demo_capacity(request: Request):
    """Switch the demo 'results-day server' (8 workers, slower database) on or off."""
    if (err := _local_only(request)):
        return err
    body = await _json(request)
    def num(key):
        try:
            return int(body[key]) if body.get(key) is not None else None
        except (TypeError, ValueError):
            return None
    capacity.set_enabled(bool(body.get("enabled", not capacity.enabled())), num("workers"), num("db_ms"))
    workers, db_ms = capacity.profile()
    ledger.event("info", f"Demo: results-day server ON ({workers} workers, {db_ms} ms database)" if capacity.enabled()
                 else "Demo: results-day server OFF (normal laptop server)", dedupe=False)
    return {"server_demo": capacity.enabled(), "workers": workers, "db_ms": db_ms}


@app.get("/api/kavach/incidents/{incident_id}/report")
def kavach_report(incident_id: str, request: Request):
    if (err := _local_only(request)):
        return err
    out = explainer.report(incident_id)
    if "error" in out:
        return JSONResponse(out, status_code=404)
    return out


@app.get("/api/kavach/incidents/{incident_id}/leaks")
def kavach_incident_leaks(incident_id: str, request: Request):
    if (err := _local_only(request)):
        return err
    return {"rows": ledger.leaks_for(incident_id)}


# ====================================================================== student-facing Kavach features
@app.post("/kavach/otp")
async def kavach_otp(request: Request):
    """Re-verification stub for a frozen account (a real system sends the code by SMS)."""
    try:
        body = await request.json()
    except ValueError:
        body = {}
    roll, code = str(body.get("roll", "")), str(body.get("otp", "")).strip()
    f = ledger.frozen(roll)
    if not f:
        return {"ok": True, "message": "Account is not paused."}
    if code != f["otp"]:
        return JSONResponse({"error": "That code is not right."}, status_code=401)
    ledger.unfreeze(roll)
    ledger.event("info", f"Account {roll} re-verified with OTP and unpaused", f["incident_id"])
    return {"ok": True, "message": "Verified. You can log in again."}


# Extensions a session is allowed to keep: whatever was already active when the student logged in.
EXT_BASELINE: dict[str, dict] = {}
STRONG_KEYS = ("ext:", "tag:", "attr:", "script:", "tamper:")   # identify one specific extension, or tampering
TAMPER = "tamper:"     # built-ins swapped to disarm Kavach (right-click / copy unblockers): never allowed, even at login


@app.post("/kavach/extension")
async def kavach_extension(request: Request):
    """Footprints from the extension guard (static/kavach-guard.js) on a logged-in page.

    phase "initial" = what the page had in its first seconds, "live" = what appeared later.
    The first report of a session becomes its baseline: extensions already active at
    login are allowed and listed on the dashboard. A footprint outside the baseline
    (an extension switched on or clicked into the page after login) ends the session.
    A report only ever affects the reporter's own session."""
    try:
        body = await request.json()
    except ValueError:
        body = {}
    phase = body.get("phase") if body.get("phase") in ("initial", "live", "ping", "contextmenu") else "live"
    items: dict[str, dict] = {}
    for it in (body.get("items") if isinstance(body.get("items"), list) else [])[:24]:
        if isinstance(it, dict) and str(it.get("key", "")).strip():
            key = str(it["key"]).strip()[:80]
            items[key] = {"key": key, "text": str(it.get("text", ""))[:120], "name": str(it.get("name") or "")[:60] or None}
    path = str(body.get("path", ""))[:100] or "?"

    token = request.cookies.get(auth.SESSION_COOKIE)
    s = auth.get_session(token)
    if not s:
        return {"action": "logout"}                          # no session to protect: just go to the login page
    if not kconfig.EXTENSION_GUARD:
        return {"action": "none", "agent": False}
    for t in [t for t in EXT_BASELINE if t not in auth.SESSIONS]:
        EXT_BASELINE.pop(t, None)

    roll, ip, device = s.roll, auth.ip_of(request), auth.device_of(request)
    who = f"{gateway._name(roll) or 'student'} ({roll})"
    now = time.time()
    on = ledger.enabled()
    base = EXT_BASELINE.get(token)
    tamper = [v for v in items.values() if v["key"].startswith(TAMPER)]
    if base is None and phase == "initial":
        # First page after login: this is the baseline. It is taken even while the agent is
        # OFF, so switching the agent ON later never resets it: anything that shows up after
        # login is caught the moment the agent is back ON. Tampering is never part of it.
        allowed = [v for v in items.values() if not v["key"].startswith(TAMPER)]
        EXT_BASELINE[token] = base = {"keys": {v["key"] for v in allowed}, "created": now}
        if allowed and on:
            _extensions_allowed(who, roll, ip, path, allowed)
        if not (tamper and on):
            return {"action": "ok" if on else "none", "agent": on}
    if not on:
        return {"action": "none", "agent": False}            # agent OFF: nothing is enforced, the guard holds its findings
    if phase == "contextmenu":
        ledger.event("warn", f"Right-click menu blocked for {who} on {path}: right-click extensions can read "
                             f"selected text without touching the page")
        return {"action": "ok", "agent": True}
    if base is None:                                         # the first-page report never arrived: start the baseline now
        EXT_BASELINE[token] = {"keys": set(items), "created": now}
        return {"action": "ok", "agent": True}

    new = [v for k, v in items.items() if k not in base["keys"]]
    if not new:
        return {"action": "ok"}
    if not tamper and now - base["created"] < kconfig.EXTENSION_BASELINE_GRACE:
        base["keys"].update(v["key"] for v in new)           # a slow extension still loading on the first page
        _extensions_allowed(who, roll, ip, path, new)
        return {"action": "ok"}
    strong = tamper or [v for v in new if v["key"].startswith(STRONG_KEYS)]
    if not strong and base["keys"]:
        # Only generic page changes (an extra element, a hooked function) and extensions were already
        # active at login: most likely one of those. Record it, don't log the student out.
        base["keys"].update(v["key"] for v in new)
        ledger.event("warn", f"New page change in {who}'s session ({new[0]['text']}), likely from an extension "
                             f"already active at login: allowed")
        return {"action": "ok"}

    flagged = strong or new
    names = sorted({v["name"] for v in flagged if v["name"]}) or ["an unidentified extension"]
    what = ", ".join(names)
    actor = {"ip": ip, "device": device[:6] + "…", "roll": roll, "name": gateway._name(roll)}
    inc = ledger.incident("extension", f"roll:{roll}", f"Browser extension connected in the session of {who}", path, actor)
    risk, sev = detector.score(["extension"])
    ledger.update_incident(inc, risk=risk, severity=sev, actor=actor,
                           action="Session ended; student sent back to the login page",
                           reasons=[(f"An extension disabled Kavach's page protections (right-click / copy blocking) "
                                     f"on {path} while {who} was logged in: {what}. Never allowed, even at login")
                                    if tamper else
                                    f"A browser extension started touching the portal page {path} after {who} "
                                    f"logged in: {what}",
                                    f"Extensions already active at login were allowed ({len(base['keys'])} footprint(s))",
                                    *[f"Signal: {v['text']}" for v in flagged[:5]]],
                           evidence=[{"signal": v["text"]} for v in flagged])
    auth.end_session(token)
    EXT_BASELINE.pop(token, None)
    ledger.bump("blocked")
    ledger.event("block", f"Extension connected after login ({what}) in {who}'s session from {ip}: logged out",
                 inc["id"], dedupe=False)
    notify.student(roll, "extension", "You were signed out: a browser extension was connected",
                   f"At {time.strftime('%H:%M')} a browser extension ({what}) started changing the portal page {path} "
                   f"after you logged in. Extensions that touch the page can read your marks, fees and ID details, "
                   f"so Kavach signed you out. Turn it off for this site, or keep it off while you use the portal.")
    notify.it_head("extension", f"Extension connected after login: {roll}",
                   f"{what} started modifying {path} from IP {ip}. Session ended.")
    resp = JSONResponse({"action": "logout", "incident": inc["id"], "names": names})
    resp.delete_cookie(auth.SESSION_COOKIE)
    return resp


def _extensions_allowed(who: str, roll: str, ip: str, path: str, items: list[dict]) -> None:
    """Dashboard note: extensions that were already active when the student logged in."""
    named = sorted({v["name"] for v in items if v["name"]})
    unnamed = sum(1 for v in items if not v["name"])
    what = ", ".join(named) + (f"{' + ' if named else ''}{unnamed} other page change(s)" if unnamed else "")
    ledger.event("warn", f"{who} logged in with browser extension(s) already active: {what}. "
                         f"Allowed for this session; a new extension will log them out.", dedupe=False)
    notify.it_head("extension", f"Extensions active at login: {roll}",
                   f"{what} on {path} from IP {ip}. Allowed because they were present before login.")


# ---------------------------------------------------------------- protected download links (agent/linkguard.py)
async def _json(request: Request) -> dict:
    try:
        body = await request.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _download_for(kind: str) -> tuple[str, dict] | tuple[None, None]:
    for path, dl in kconfig.PROTECTED_DOWNLOADS.items():
        if dl["kind"] == kind:
            return path, dl
    return None, None


def _doc_label(dl: dict, ref: str) -> str:
    return f"semester {ref} {dl['doc']}" if dl["kind"] == "acknowledgement" else f"{dl['doc']} {ref}"


@app.post("/kavach/ticket")
async def kavach_ticket(request: Request):
    """One-time download ticket for a protected download button (bound to session + document)."""
    body = await _json(request)
    token = request.cookies.get(auth.SESSION_COOKIE)
    s = auth.get_session(token)
    if not s:
        return JSONResponse({"error": "Please log in."}, status_code=401)
    if not ledger.enabled():
        return {"ticket": None, "agent": False}              # agent OFF: the plain link works, nothing to bind
    path, dl = _download_for(str(body.get("kind", "")))
    if not path:
        return JSONResponse({"error": "Unknown download."}, status_code=400)
    user_id, ref = str(body.get("userId", ""))[:20], str(body.get("ref", ""))[:20]
    if user_id != s.roll:
        return JSONResponse({"blocked": True, "by": "Kavach", "reason": f"That {dl['doc']} does not belong to you."},
                            status_code=403)
    return {"ticket": linkguard.issue(token, path, user_id, ref), "agent": True}


@app.post("/kavach/link")
async def kavach_link(request: Request):
    """The guard saw a protected download link being dragged (event "drag") and where it ended up ("drop")."""
    body = await _json(request)
    token = request.cookies.get(auth.SESSION_COOKIE)
    s = auth.get_session(token)
    if not s:
        return JSONResponse({"error": "Please log in."}, status_code=401)
    if not ledger.enabled():
        return {"ok": True, "agent": False}
    sid = str(body.get("id", ""))
    _, dl = _download_for(str(body.get("kind", "")))
    if not linkguard.ID_RX.match(sid) or not dl:
        return JSONResponse({"error": "Bad link."}, status_code=400)
    event = "drop" if body.get("event") == "drop" else "drag"
    ref = str(body.get("ref", ""))[:20] or "?"
    label = _doc_label(dl, ref)                              # e.g. "fee receipt CH250047", "semester 5 course acknowledgement"
    where = str(body.get("where", ""))[:120]
    path = str(body.get("path", ""))[:100] or "?"
    roll, ip, device = s.roll, auth.ip_of(request), auth.device_of(request)
    who = f"{gateway._name(roll) or 'student'} ({roll})"
    actor = {"ip": ip, "device": device[:6] + "…", "roll": roll, "name": gateway._name(roll)}
    inc = ledger.incident("download_link", f"roll:{roll}:{dl['kind']}",
                          f"{dl['doc'].capitalize()} link moved out of the {dl['page']} page by {who}", path, actor)
    rec = linkguard.remember(sid, roll, dl["kind"], ref, path, inc["id"])
    risk, sev = detector.score(["download_link"])
    if event == "drag":
        ledger.update_incident(inc, risk=risk, severity=sev, actor=actor, protected=1,
                               action="Link scrambled before it left the page: the dragged copy is a dead end",
                               reasons=[f"{who} started dragging the {label} download link out of {path}",
                                        "The real download URL was never on the page; the drag carried "
                                        f"/kavach/scrambled/{sid[:8]}…, which downloads nothing"])
        ledger.bump("protected")
        ledger.event("block", f"{label.capitalize()} link dragged by {who}: link scrambled (dead end)", inc["id"],
                     dedupe=False)
    else:
        rec["dropped"] = where or "outside the page"
        ledger.update_incident(inc, risk=min(100, risk + 10), severity=detector.severity(min(100, risk + 10)), actor=actor,
                               reasons=[f"The dragged {dl['doc']} link was dropped {rec['dropped']}"])
        ledger.event("warn", f"Scrambled {label} link from {who} was dropped {rec['dropped']}", inc["id"], dedupe=False)
        notify.it_head("download_link", f"{dl['doc'].capitalize()} link moved out of the portal: {roll}",
                       f"The {label} link was dragged out of {path} and dropped {rec['dropped']}. It was scrambled "
                       f"first, so it downloads nothing elsewhere.")
    return {"ok": True, "agent": True, "incident": inc["id"]}


@app.get("/kavach/scrambled/{sid}")
def kavach_scrambled(sid: str, request: Request):
    """Where a scrambled download link leads: nowhere. Logged so the IT head sees the attempt."""
    rec = linkguard.lookup(sid) if linkguard.ID_RX.match(sid) else None
    ip = auth.ip_of(request)
    s = auth.current_session(request)
    opener = f"{gateway._name(s.roll) or 'student'} ({s.roll})" if s else f"anonymous visitor @ {ip}"
    if rec:
        _, dl = _download_for(rec["kind"])
        label = _doc_label(dl, rec["ref"]) if dl else "download"
        rec["opened"] += 1
        inc = ledger.INCIDENTS.get(rec["incident_id"])
        if inc:
            ledger.update_incident(inc, protected=1, reasons=[f"The scrambled link was opened by {opener} from IP {ip}: "
                                                              f"nothing was downloaded"])
        ledger.event("block", f"Scrambled {label} link (moved by {rec['roll']}) opened by {opener}: refused",
                     rec["incident_id"], dedupe=False)
        notify.it_head("download_link", f"Scrambled {label} link opened",
                       f"Opened by {opener} from IP {ip}. Nothing was downloaded.")
    else:
        ledger.event("warn", f"Unknown scrambled download link opened by {opener} from {ip}: refused")
    return actions.blocked_response(request, "Kavach scrambled this download link because it was moved out of the portal. "
                                    "It downloads nothing. Open the portal page and use its download button.",
                                    rec["incident_id"] if rec else None, code="download_link")


def _session_or_401(request: Request):
    s = auth.current_session(request)
    if not s:
        return None, JSONResponse({"error": "Please log in."}, status_code=401)
    return s, None


@app.get("/api/me/alerts")
def my_alerts(request: Request):
    s, err = _session_or_401(request)
    if err:
        return err
    devices = ledger.devices_for(s.roll)
    current = auth.device_of(request)
    trusted = {d["device"] for d in devices if d["trusted"]}
    alerts = notify.for_student(s.roll)
    for a in alerts:                                     # new-device alerts: has the student already confirmed it?
        act = a.get("action") or {}
        if act.get("type") == "new_device" and act.get("device"):
            act["trusted"] = act["device"] in trusted
            act["this_device"] = act["device"] == s.device   # same test as /api/me/trust-device
    return {
        "unread": notify.unread(s.roll),
        "alerts": alerts,
        "agent_on": ledger.enabled(),
        "this_device": {"trusted": s.trusted, "id": current[:6] + "…"},
        "devices": [{"id": d["device"][:6] + "…", "trusted": bool(d["trusted"]), "first_seen": d["first_seen"],
                     "current": d["device"] == current} for d in devices],
        "sessions": [{"ip": x.ip, "device": x.device[:6] + "…", "created": x.created, "last_seen": x.last_seen,
                      "current": x.token == s.token, "trusted": x.trusted} for x in auth.sessions_for(s.roll)],
    }


@app.post("/api/me/alerts/read")
def my_alerts_read(request: Request):
    s, err = _session_or_401(request)
    if err:
        return err
    notify.mark_read(s.roll)
    return {"ok": True}


@app.post("/api/me/trust-device")
async def trust_device(request: Request):
    """Trust the device a new-device alert was about (body {"device": ...}), or this device."""
    s, err = _session_or_401(request)
    if err:
        return err
    body = await _json(request)
    device = str(body.get("device") or s.device)
    if device != s.device and ledger.device_status(s.roll, device) == "new":
        return JSONResponse({"error": "That device has never signed in to your account."}, status_code=404)
    ledger.remember_device(s.roll, device, trusted=True)
    for x in auth.sessions_for(s.roll):
        if x.device == device:
            x.trusted = True
    which = "their current device" if device == s.device else f"device {device[:6]}…"
    ledger.event("info", f"Student {s.roll} marked {which} as trusted")
    return {"ok": True, "this_device": device == s.device}


@app.post("/api/me/not-me")
def not_me(request: Request):
    """'This wasn't me': end every other session for this account and tell the IT head."""
    s, err = _session_or_401(request)
    if err:
        return err
    n = auth.end_all_sessions(s.roll, except_token=s.token)
    ledger.event("warn", f"Student {s.roll} reported a sign-in that wasn't them: ended {n} other session(s)")
    notify.it_head("not_me", f"Student {s.roll} reported an unrecognised sign-in", f"{n} other session(s) ended.")
    return {"ok": True, "ended": n}


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "Not found."}, status_code=404)
    return Response((STATIC / "404.html").read_text(encoding="utf-8"), status_code=404, media_type="text/html")
