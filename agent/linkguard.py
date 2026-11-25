"""Link guard for protected downloads (fee receipts, course acknowledgements): tab tickets and scrambled links.

While the agent is ON:
  * the page never shows the real download URL. Each protected download link
    ("Generate receipt", "Download acknowledgement") points to a random dead end
    (/kavach/scrambled/<id>), and the guard script keeps the real URL in memory.
  * a click asks for a one-time ticket bound to the session, download, student and document,
    then downloads with it in a header. A link opened in another tab, pasted into
    another site or typed by hand cannot send that header, so the gateway refuses it.
  * dragging a protected link is reported here. The dragged copy is the dead end, and
    opening it is refused and logged.
"""
from __future__ import annotations

import re
import secrets
import threading
import time

from . import config

_lock = threading.Lock()
TICKETS: dict[str, dict] = {}         # ticket -> {session, path, user_id, ref, until}
SCRAMBLED: dict[str, dict] = {}       # scrambled id -> {roll, kind, ref, ts, dropped, incident_id, path}
ID_RX = re.compile(r"^[A-Za-z0-9]{8,64}$")


def _purge(now: float) -> None:
    for t in [t for t, v in TICKETS.items() if v["until"] < now]:
        TICKETS.pop(t, None)
    for k in [k for k, v in SCRAMBLED.items() if now - v["ts"] > 24 * 3600]:
        SCRAMBLED.pop(k, None)


def issue(session_token: str, path: str, user_id: str, ref: str) -> str:
    now = time.time()
    ticket = secrets.token_urlsafe(24)
    with _lock:
        _purge(now)
        TICKETS[ticket] = {"session": session_token, "path": path, "user_id": user_id, "ref": ref,
                           "until": now + config.LINK_TICKET_SECONDS}
    return ticket


def redeem(ticket: str | None, session_token: str | None, path: str, user_id: str, ref: str) -> tuple[bool, str]:
    """Use up a ticket. (ok, reason why not)."""
    button = config.PROTECTED_DOWNLOADS.get(path, {}).get("button", "download")
    if not ticket:
        return False, (f"No tab ticket: the link was opened directly (new tab, another website or a pasted URL), "
                       f"not through the {button} button")
    with _lock:
        t = TICKETS.pop(ticket, None)
    if not t:
        return False, "The download ticket is unknown or was already used (tickets work once)"
    if t["until"] < time.time():
        return False, f"The download ticket expired (valid {config.LINK_TICKET_SECONDS} s)"
    if t["session"] != session_token:
        return False, "The download ticket belongs to a different login session"
    if t["path"] != path or t["user_id"] != user_id or t["ref"] != ref:
        return False, "The download ticket was issued for a different document"
    return True, ""


def remember(sid: str, roll: str, kind: str, ref: str, path: str, incident_id: str | None) -> dict:
    with _lock:
        _purge(time.time())
        rec = SCRAMBLED.setdefault(sid, {"roll": roll, "kind": kind, "ref": ref, "ts": time.time(), "dropped": None,
                                         "incident_id": incident_id, "path": path, "opened": 0})
        rec["incident_id"] = incident_id or rec["incident_id"]
        return rec


def lookup(sid: str) -> dict | None:
    return SCRAMBLED.get(sid)


def reset() -> None:
    with _lock:
        TICKETS.clear()
        SCRAMBLED.clear()
