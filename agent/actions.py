"""Response actions: block an IP + device, freeze an account, end a session, stop a response, notify."""
from __future__ import annotations

import html
import time
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app import auth
from . import ledger, notify

BLOCKED_TEMPLATE = Path(__file__).resolve().parent.parent / "static" / "blocked.html"


def wants_html(request: Request) -> bool:
    return not request.url.path.startswith("/api/") and "text/html" in request.headers.get("accept", "")


def blocked_response(request: Request, reason: str, incident_id: str | None, *, code: str = "blocked",
                     status: int = 403, extra: dict | None = None):
    """The attacker sees a clean branded page (or JSON for API calls), never a stack trace."""
    ip = getattr(request.state, "ip", "?")
    if wants_html(request):
        page = (BLOCKED_TEMPLATE.read_text(encoding="utf-8")
                .replace("{{reason}}", html.escape(reason))
                .replace("{{incident}}", html.escape(incident_id or "-"))
                .replace("{{ip}}", html.escape(ip))
                .replace("{{time}}", time.strftime("%d %b %Y, %H:%M:%S")))
        return HTMLResponse(page, status_code=status)
    body = {"blocked": True, "by": "Kavach", "code": code, "reason": reason, "incident": incident_id}
    body.update(extra or {})
    return JSONResponse(body, status_code=status)


def session_ended_response(request: Request, reason: str):
    if wants_html(request):
        resp = RedirectResponse("/student/login?kavach=session_ended", status_code=303)
    else:
        resp = JSONResponse({"error": "Your session was ended by Kavach. Please log in again.",
                             "kavach": "session_ended", "reason": reason}, status_code=401)
    resp.delete_cookie(auth.SESSION_COOKIE)
    return resp


def block_actor(ip: str, device: str | None, reason: str, inc: dict, *, whole_ip: bool = False) -> None:
    ledger.block(ip, None if whole_ip else device, reason, inc["id"])
    who = f"IP {ip}" if whole_ip else f"IP {ip} + device {short(device)}"
    ledger.event("block", f"Blocked {who} for 15 min: {reason}", inc["id"], dedupe=False)
    notify.it_head("block", f"Blocked {who}", reason)


def freeze_account(roll: str, reason: str, inc: dict) -> None:
    if ledger.frozen(roll):
        return
    f = ledger.freeze(roll, reason, inc["id"])
    ended = auth.end_all_sessions(roll)
    ledger.event("block", f"Froze account {roll} and ended {ended} session(s): {reason}", inc["id"], dedupe=False)
    ledger.event("info", f"OTP re-verification sent to the registered phone of {roll} (demo stub, code {f['otp']})", inc["id"])
    notify.student(roll, "frozen", "Your account was paused for your safety",
                   f"Kavach saw your account being used to read other students' records ({reason}). "
                   f"We ended all sessions. To log in again, verify the one-time code sent to your "
                   f"registered phone. (Demo stub: your code is {f['otp']}.)")


def end_session(token: str, code: str, reason: str, roll: str, inc: dict | None) -> None:
    auth.end_session(token)
    level = "block" if code == "session_hijack" else "info"
    ledger.event(level, f"Ended session of {roll}: {reason}", inc["id"] if inc else None)


def short(device: str | None) -> str:
    return (device or "?")[:6] + "…"
