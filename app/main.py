"""FastAPI app: the portal, the Kavach dashboard and the agent middleware in one process."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from agent import detector, explainer, gateway, ledger, notify
from agent import config as kconfig
from . import auth, db, portal

STATIC = Path(__file__).resolve().parent.parent / "static"
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.seed()
    ledger.load()
    yield


app = FastAPI(title="Kavach demo", docs_url=None, redoc_url=None, lifespan=lifespan)
app.middleware("http")(gateway.kavach_gateway)          # every request and response passes through Kavach
app.mount("/static", StaticFiles(directory=STATIC), name="static")
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
    return FileResponse(STATIC / "dashboard.html", headers={"Cache-Control": "no-store"})


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
    ledger.event("info", "Demo reset: ledger, blocks, sessions and portal lockouts cleared", dedupe=False)
    return {"ok": True, "enabled": ledger.enabled()}


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
    return {
        "unread": notify.unread(s.roll),
        "alerts": notify.for_student(s.roll),
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
def trust_device(request: Request):
    s, err = _session_or_401(request)
    if err:
        return err
    ledger.remember_device(s.roll, s.device, trusted=True)
    s.trusted = True
    ledger.event("info", f"Student {s.roll} marked their current device as trusted")
    return {"ok": True}


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
