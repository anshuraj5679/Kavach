"""Kavach gateway: middleware that every request and every response passes through.

    request -> inspector -> (portal + DB) -> scanner -> detector -> actions -> ledger -> dashboard

Rules decide. Nothing here asks an LLM anything.
"""
from __future__ import annotations

import json
import re
import secrets
import time
from functools import lru_cache

from fastapi import Request
from starlette.responses import Response

from app import auth, db
from . import actions, config, detector, inspector, ledger, notify, scanner

DEVICE_RX = re.compile(r"^[A-Za-z0-9_-]{20,40}$")
DEVICE_MAX_AGE = 400 * 24 * 3600


@lru_cache(maxsize=4096)
def _name(roll: str | None) -> str | None:
    if not roll:
        return None
    with db.connect() as conn:
        row = conn.execute("SELECT name FROM students WHERE roll = ?", (roll,)).fetchone()
    return row["name"] if row else None


def _who(roll: str | None, ip: str) -> str:
    return f"{_name(roll) or 'student'} ({roll})" if roll else f"anonymous visitor @ {ip}"


async def kavach_gateway(request: Request, call_next):
    # Every browser gets a secret device ID (feature 1-3 track IP + device, never MAC:
    # a website cannot read a MAC address).
    device = request.cookies.get(auth.DEVICE_COOKIE, "")
    new_device = not DEVICE_RX.match(device)
    if new_device:
        device = secrets.token_urlsafe(18)
    request.state.device = device
    request.state.ip = ip = inspector.client_ip(request)
    path = request.url.path

    if not ledger.enabled() or path.startswith(config.EXEMPT_PREFIXES):
        resp = await call_next(request)          # agent OFF: straight to the portal, nothing inspected
    else:
        resp = await _guard(request, call_next, ip, device, path)
    if new_device:
        resp.set_cookie(auth.DEVICE_COOKIE, device, max_age=DEVICE_MAX_AGE, httponly=True, samesite="lax")
    return resp


async def _guard(request: Request, call_next, ip: str, device: str, path: str):
    ledger.bump("inspected")
    token = request.cookies.get(auth.SESSION_COOKIE)
    session = auth.get_session(token)
    roll = session.roll if session else None
    actor_key = f"{ip}|{device}"
    actor = {"ip": ip, "device": actions.short(device), "roll": roll, "name": _name(roll)}
    who = _who(roll, ip)
    detector.hit("req", actor_key)
    touched: list[dict] = []

    # ---- 0. already blocked? ---------------------------------------------------
    b = ledger.blocked(ip, device)
    if b:
        ledger.bump("blocked")
        record_ep = path in config.OWNER_PARAMS or path.startswith(("/api/library", "/api/admissions"))
        inc = ledger.INCIDENTS.get(b["incident_id"])
        if inc:
            ledger.update_incident(inc, protected=1 if record_ep else 0)
        if record_ep:
            ledger.bump("protected")
        ledger.event("block", f"Refused {request.method} {path} from blocked {ip}", b["incident_id"])
        return actions.blocked_response(request, b["reason"], b["incident_id"])

    # ---- 1. session guard (features 2 + 3) -------------------------------------
    if session:
        problem = inspector.session_problem(session, device, ip)
        if problem:
            code, reason = problem
            inc = None
            if code == "session_hijack":
                inc = ledger.incident("session_hijack", f"roll:{roll}", f"Session of {who} replayed from another device",
                                      path, actor)
                risk, sev = detector.score(["session_hijack"])
                ledger.update_incident(inc, risk=risk, severity=sev, action="Session ended, student notified", reasons=[
                    reason,
                    f"Created on device {actions.short(session.device)} at {session.ip}; "
                    f"reused from device {actions.short(device)} at {ip}",
                ])
                notify.student(roll, "hijack", "Your session was used from another device",
                               f"At {time.strftime('%H:%M')} someone reused your login cookie from a different device "
                               f"(IP {ip}). Kavach ended that session. If you left a lab PC logged in, this is why. "
                               f"Use 'Log out from all devices' if you are unsure.", {"type": "logout_all"})
                notify.it_head("hijack", f"Session hijack attempt on {roll}", reason)
                ledger.bump("blocked")
            actions.end_session(token, code, reason, roll, inc)
            return actions.session_ended_response(request, reason)
        f = ledger.frozen(roll)
        if f:
            auth.end_session(token)
            ledger.bump("blocked")
            return actions.blocked_response(request, "Account paused by Kavach: re-verification (OTP) required.",
                                            f["incident_id"], code="otp_required", extra={"otp_required": True, "roll": roll})

    body = await request.body() if request.method in ("POST", "PUT", "PATCH") else b""
    login_roll = _login_roll(path, request, body) if path in config.LOGIN_ENDPOINTS else None
    if login_roll and ledger.frozen(login_roll):
        f = ledger.frozen(login_roll)
        return actions.blocked_response(request, "This account is paused after suspicious activity. Verify the "
                                        "one-time code sent to your registered phone to continue.",
                                        f["incident_id"], code="otp_required", extra={"otp_required": True, "roll": login_roll})

    # ---- 2. SQL injection: stop it before the database is touched ---------------
    sqli = inspector.find_sqli(inspector.request_values(request, body))
    if sqli:
        inc = ledger.incident("sqli", actor_key, f"SQL injection attempt on {path}", path, actor)
        risk, sev = detector.score(["sqli"])
        actions.block_actor(ip, device, "SQL injection attempt", inc)
        ledger.update_incident(inc, risk=risk, severity=sev, protected=1,
                               action="Request blocked before the database; IP + device blocked 15 min",
                               reasons=[f"Parameter '{sqli['param']}' contains {sqli['pattern']}",
                                        "The query never ran, so the applicant table could not be dumped"],
                               evidence=[{"param": sqli["param"], "payload": sqli["value"]}])
        ledger.bump("blocked")
        ledger.bump("protected")
        ledger.event("critical", f"SQL injection from {ip} on {path} stopped before the database", inc["id"], dedupe=False)
        return actions.blocked_response(request, f"SQL injection pattern detected ({sqli['pattern']}).", inc["id"], code="sqli")

    # ---- 3. ownership: is this person asking for someone else's record? --------
    flagged = None
    mm = inspector.ownership_mismatch(path, request, session)
    if mm:
        detector.hit("target", roll, tag=mm["requested"])
        if path in config.ZERO_TOLERANCE_ENDPOINTS:
            n = detector.hit("receipt_idor", actor_key)
            inc = ledger.incident("receipt_idor", actor_key, "Fee-receipt IDOR: reading another student's receipt", path, actor)
            codes = ["receipt_idor"] + (["foreign_over_limit"] if n >= config.RECEIPT_IDOR_LIMIT else [])
            risk, sev = detector.score(codes)
            action = "Request refused (403) before the receipt was read"
            if n >= config.RECEIPT_IDOR_LIMIT:
                actions.block_actor(ip, device, f"{n} attempts to read other students' fee receipts", inc)
                action += "; IP + device blocked 15 min"
            ledger.update_incident(inc, risk=risk, severity=sev, action=action, protected=1, actor=actor, reasons=[
                f"{who} changed userId to {mm['requested']} on the receipt link (own id is {mm['own']})",
                "Fee receipts are financial documents: zero tolerance for foreign access",
            ], evidence=[{"asked_for": mm["requested"], "own": mm["own"]}])
            ledger.bump("blocked")
            ledger.bump("protected")
            ledger.event("block", f"Receipt IDOR: {who} asked for userId={mm['requested']}, refused", inc["id"])
            return actions.blocked_response(request, f"Receipt {mm['requested']} does not belong to the logged-in student.",
                                            inc["id"], code="ownership")
        flagged = ledger.incident("idor_scrape", f"roll:{roll}", f"Results scraping by {who} via ?{mm['param']}=", path, actor)
        seen = detector.count("foreign", roll)
        if seen >= config.FOREIGN_RECORD_LIMIT:
            risk, sev = detector.score(["foreign_over_limit", "ownership_mismatch", "anomaly"])
            actions.block_actor(ip, device, f"Read {seen} other students' results", flagged)
            actions.freeze_account(roll, f"read {seen} other students' results", flagged)
            ledger.update_incident(flagged, risk=risk, severity=sev, protected=1, actor=actor,
                                   action=f"Blocked IP + device, froze account {roll}, OTP re-verification required",
                                   reasons=[f"Crossed the limit of {config.FOREIGN_RECORD_LIMIT} foreign records in "
                                            f"{config.WINDOW_SECONDS // 60} min; every further request is refused"])
            ledger.bump("blocked")
            ledger.bump("protected")
            return actions.blocked_response(request, "Too many requests for other students' records.", flagged["id"], code="scrape")

    # ---- 4. the portal (and its database) --------------------------------------
    resp = await call_next(request)

    # ---- 5. login outcomes (feature 1: lockout shield, feature 3: new devices) --
    if path in config.LOGIN_ENDPOINTS:
        if resp.status_code == 401:
            _failed_login(request, path, ip, device, actor_key, actor, login_roll)
        elif resp.status_code == 200 and path == "/api/auth/step2":
            _successful_login(resp, ip, device)

    # ---- 6. scan what is leaving ----------------------------------------------
    if "application/json" not in resp.headers.get("content-type", ""):
        return resp
    raw = b"".join([chunk async for chunk in resp.body_iterator])
    try:
        payload = json.loads(raw)
    except ValueError:
        return _rebuild(resp, raw)
    res = scanner.scan(payload, roll, path)
    foreign_n = len(res.foreign)

    if foreign_n > config.ROW_SPIKE_LIMIT:                       # mass dump: stop the whole response
        inc = ledger.incident("mass_dump", actor_key, f"Mass data dump from {path}", path, actor)
        fields = sorted({f for h in res.foreign for f in h.masked})
        risk, sev = detector.score(["mass_dump", "pii_masked"] if fields else ["mass_dump"])
        ledger.update_incident(inc, risk=risk, severity=sev, protected=foreign_n,
                               action="Response stopped: nothing left the server",
                               reasons=[f"One response carried {foreign_n} other people's records (limit {config.ROW_SPIKE_LIMIT})",
                                        f"Fields inside: {', '.join(fields) or 'record data'}"],
                               evidence=[h.sample for h in res.foreign[:2]])
        ledger.bump("blocked")
        ledger.bump("protected", foreign_n)
        ledger.event("block", f"Stopped a {foreign_n}-record dump of {path} to {who}", inc["id"], dedupe=False)
        return actions.blocked_response(request, f"Response stopped: {foreign_n} other people's records in one reply "
                                        f"(limit {config.ROW_SPIKE_LIMIT}).", inc["id"], code="mass_dump")

    if res.private_leaks:                                        # someone else's private record went out
        inc = flagged or ledger.incident("private_exposure", actor_key, f"Private records exposed on {path}", path, actor)
        n = detector.hit("foreign", roll or actor_key, n=len(res.private_leaks))
        rows = [{"record_id": h.record_id, "owner_name": h.name, "fields": ["name"] + h.private + h.masked,
                 "to_whom": who, "ip": ip, "endpoint": path, "incident_id": inc["id"], "outcome": "leaked"}
                for h in res.private_leaks]
        added = ledger.add_leaks(rows)
        risk, sev = detector.score(["ownership_mismatch"] * min(n, 3))
        ledger.update_incident(inc, risk=risk, severity=sev, leaked=added, actor=actor,
                               action=f"Watching: {n} of {config.FOREIGN_RECORD_LIMIT} foreign records used, blocked on the next",
                               reasons=[f"{who} is reading other students' records by editing the URL "
                                        f"(no ownership check in the portal)"],
                               evidence=[{"record": h.record_id, "name": h.name, "fields": h.private} for h in res.private_leaks])
        ledger.bump("leaked", added)
        for h in res.private_leaks:
            ledger.event("leak", f"LEAKED: {h.name} ({h.record_id}) {', '.join(h.private)} -> {who}", inc["id"], dedupe=False)
        touched.append(inc)

    if res.masked_records:                                       # other people's PII: masked in flight
        hits = res.masked_records
        fields = sorted({f for h in hits for f in h.masked})
        inc = ledger.incident("overexposure", f"endpoint:{path}", f"Over-exposure: {path} sends personal data the page never shows",
                              path, actor)
        risk = min(75, 30 + len(hits))
        rows = [{"record_id": h.record_id, "owner_name": h.name, "fields": h.masked, "to_whom": who,
                 "ip": ip, "endpoint": path, "incident_id": inc["id"], "outcome": "masked"} for h in hits]
        added = ledger.add_leaks(rows)
        ledger.update_incident(inc, risk=risk, severity=detector.severity(risk), protected=added, actor=actor,
                               action="Masked in flight: the browser never received the real values",
                               reasons=[f"The API returned {', '.join(fields)} for {len(hits)} other people in one reply",
                                        "The page only displays non-sensitive columns, so this data had no reason to leave"],
                               evidence=[h.sample for h in hits[:2]])
        ledger.bump("protected", added)
        ledger.event("protect", f"Masked {', '.join(fields)} in {len(hits)} records sent to {who} ({path})", inc["id"])
        touched.append(inc)

    if res.stripped_passwords:
        ledger.event("protect", f"Removed {res.stripped_passwords} plain-text password field(s) from a response on {path}")

    # ---- 7. optional anomaly model: can raise a score, never decides -----------
    if path.startswith("/api/") and detector.ANOMALY.model is not None:
        a = detector.ANOMALY.score(detector.actor_features(actor_key, roll, res.records))
        if a and a >= 0.3:
            now = time.time()
            touched += [i for i in list(ledger.INCIDENTS.values()) if i not in touched and now - i["last_seen"] < 2
                        and i["actor_key"] in (actor_key, f"roll:{roll}")]
            for inc in touched:
                if any(r.startswith("Anomaly model") for r in inc["reasons"]):
                    continue                    # counts once per incident
                ledger.update_incident(inc, risk=min(100, inc["risk"] + config.RISK_WEIGHTS["anomaly"]),
                                       reasons=[f"Anomaly model: behaviour unlike normal students (score {a})"])
            if not touched:
                ledger.event("info", f"Anomaly model: unusual pattern from {ip} (score {a}); no rule fired, so no action")

    changed = bool(res.masked_records or res.stripped_passwords)
    return _rebuild(resp, json.dumps(payload).encode() if changed else raw)


# ------------------------------------------------------------------------- helpers
def _rebuild(resp: Response, body: bytes) -> Response:
    new = Response(content=body, status_code=resp.status_code, media_type=resp.media_type or "application/json")
    for k, v in resp.raw_headers:
        if k not in (b"content-length", b"content-type"):
            new.raw_headers.append((k, v))
    return new


def _login_roll(path: str, request: Request, body: bytes) -> str | None:
    if path == "/api/auth/step1":
        try:
            return str(json.loads(body or b"{}").get("roll", "")).strip() or None
        except (ValueError, AttributeError):
            return None
    pending = auth.PENDING.get(request.cookies.get(auth.PENDING_COOKIE, ""))
    return pending["roll"] if pending else None


def _cookie_from(resp: Response, name: str) -> str | None:
    prefix = name.encode() + b"="
    for k, v in resp.raw_headers:
        if k == b"set-cookie" and v.startswith(prefix):
            return v[len(prefix):].split(b";")[0].decode()
    return None


def _failed_login(request: Request, path: str, ip: str, device: str, actor_key: str, actor: dict, target: str | None) -> None:
    n = detector.hit("fail", actor_key)
    ip_n = detector.hit("fail_ip", ip)
    what = "date-of-birth" if path.endswith("step1") else "ID-card"
    shared = ledger.ip_has_blocked_device(ip, device)
    limit = config.SHARED_IP_LOGIN_LIMIT if shared else config.FAILED_LOGIN_LIMIT
    target = target or "?"
    if n < 3 and ip_n < config.IP_FAILED_LOGIN_CEILING and n < limit:     # tolerate the odd typo
        ledger.event("warn", f"Failed login ({what}) for USN {target} from {ip}: {n}/{limit}")
        return
    inc = ledger.incident("login_attack", actor_key, f"Credential guessing against USN {target}", path, actor)
    reasons = [f"{n} wrong {what} attempts for USN {target} from IP {ip}, device {actions.short(device)} "
               f"within {config.WINDOW_SECONDS // 60} min"]
    if shared:
        reasons.append(f"Another device on {ip} is already blocked, so this device gets only {limit} tries")
    if n >= limit or ip_n >= config.IP_FAILED_LOGIN_CEILING:
        whole_ip = ip_n >= config.IP_FAILED_LOGIN_CEILING
        if whole_ip:
            reasons.append(f"{ip_n} failures from {ip} across devices (cookie-dropping): whole IP blocked")
        actions.block_actor(ip, device, f"{n} failed logins for USN {target}", inc, whole_ip=whole_ip)
        risk, sev = detector.score(["login_flood", "failed_login"])
        ledger.update_incident(inc, risk=risk, severity=sev, reasons=reasons, protected=1,
                               action=f"Blocked the attacker after {n} tries, before the portal's own "
                                      f"{config.PORTAL_USN_LOCK_AFTER}-try lock. USN {target} stays usable for the real student.")
        if target != "?":
            notify.student(target, "lockout_shield", "Someone tried to get into your account",
                           f"Someone tried your account {n}× from IP {ip} on a device you don't use. Kavach blocked "
                           f"that device. Your account is NOT locked: you can still log in normally.",
                           {"type": "logout_all"})
        notify.it_head("lockout_shield", f"Lockout attack on USN {target} blocked",
                       f"{n} wrong {what} attempts from {ip}. Attacker blocked; student notified and still able to log in.")
        ledger.bump("protected")
    else:
        risk, sev = detector.score(["failed_login"] * n)
        ledger.update_incident(inc, risk=risk, severity=sev, reasons=reasons, action=f"Watching: {n}/{limit} tries")
        ledger.event("warn", f"Failed login ({what}) for USN {target} from {ip}: {n}/{limit}", inc["id"])


def _successful_login(resp: Response, ip: str, device: str) -> None:
    s = auth.get_session(_cookie_from(resp, auth.SESSION_COOKIE))
    if not s:
        return
    status = ledger.device_status(s.roll, device)
    s.trusted = status == "trusted"
    if status == "new":
        ledger.remember_device(s.roll, device)
        notify.student(s.roll, "new_device", "New sign-in on a device we haven't seen",
                       f"Signed in at {time.strftime('%H:%M')} from IP {ip} on a new device. Until you confirm it, "
                       f"Kavach keeps this device on short sessions ({config.UNTRUSTED_IDLE_SECONDS // 60} min idle, "
                       f"{config.UNTRUSTED_MAX_SECONDS // 60} min max, ends if the network changes). "
                       f"Not you? Log out everywhere.", {"type": "new_device", "device": device})
        ledger.event("info", f"New-device login for {s.roll} from {ip}: marked untrusted, student notified")
