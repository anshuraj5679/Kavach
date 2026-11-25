"""Northfield Institute of Technology & Management: the fictional campus portal.

DEMO ARTIFACT. This file contains DELIBERATE security weak spots so that data
leaks are real and demonstrable. Every insecure line is marked `# WEAK SPOT`
and followed by `# SAFE VERSION:` showing the correct code. Do not copy the
weak versions into anything real.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from . import auth, db, pdf

router = APIRouter()
STATIC = Path(__file__).resolve().parent.parent / "static"


# ====================================================================== pages
def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


_ASSET_RX = re.compile(r'((?:src|href)=")(/static/[^"?#]+)(")')


def versioned(page: str) -> str:
    """Add ?v=<file modified time> to every /static/ asset in a page, so a browser
    always fetches a script or stylesheet again after it changes (no stale copies)."""
    def stamp(m: re.Match) -> str:
        try:
            v = int((STATIC / m[2][len("/static/"):]).stat().st_mtime)
        except OSError:
            return m[0]
        return f"{m[1]}{m[2]}?v={v}{m[3]}"
    return _ASSET_RX.sub(stamp, page)


def render(page: str, title: str, request: Request, *, scripts: str = "") -> HTMLResponse:
    s = auth.current_session(request)
    if s:
        name = _student_name(s.roll) or s.roll
        first = html.escape(name.split()[0])
        user_nav = (f'<a class="nav-user" href="/account" aria-label="Account and security for {html.escape(name)}">'
                    f'<span class="avatar" aria-hidden="true">{html.escape(name[:1])}</span>{first}'
                    f'<span class="bell" id="bell" hidden aria-label="unread security alerts">0</span></a>'
                    f'<a class="btn btn-ghost btn-sm" href="/logout">Log out</a>')
        # Kavach extension guard: only logged-in pages carry data worth reading off the screen.
        scripts = '<script src="/static/kavach-guard.js"></script>\n  ' + scripts
    else:
        user_nav = '<a class="btn btn-gold btn-sm" href="/student/login">Student login</a>'
    body = _read(f"pages/{page}.html")
    out = (_read("layout.html")
           .replace("{{title}}", html.escape(title))
           .replace("{{user_nav}}", user_nav)
           .replace("{{content}}", body)
           .replace("{{scripts}}", scripts)
           .replace(f'data-nav="{page}"', f'data-nav="{page}" aria-current="page"'))
    return HTMLResponse(versioned(out), headers={"Cache-Control": "no-store"})


def _student_name(roll: str) -> str | None:
    with db.connect() as conn:
        row = conn.execute("SELECT name FROM students WHERE roll = ?", (roll,)).fetchone()
    return row["name"] if row else None


def _login_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(f"/student/login?next={request.url.path}", status_code=303)


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render("home", "Northfield Institute of Technology & Management", request,
                  scripts='<script src="/static/home.js" defer></script>')


@router.get("/student/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render("login", "Student login", request, scripts='<script src="/static/login.js" defer></script>')


@router.get("/results", response_class=HTMLResponse)
def results_page(request: Request):
    if not auth.current_session(request):
        return _login_redirect(request)
    return render("results", "Results", request, scripts='<script src="/static/results.js" defer></script>')


@router.get("/library", response_class=HTMLResponse)
def library_page(request: Request):
    return render("library", "Library", request, scripts='<script src="/static/library.js" defer></script>')


@router.get("/admissions", response_class=HTMLResponse)
def admissions_page(request: Request):
    return render("admissions", "Admissions", request, scripts='<script src="/static/admissions.js" defer></script>')


@router.get("/acknowledgement", response_class=HTMLResponse)
def acknowledgement_page(request: Request):
    if not auth.current_session(request):
        return _login_redirect(request)
    return render("acknowledgement", "Course acknowledgement", request,
                  scripts='<script src="/static/acknowledgement.js" defer></script>')


@router.get("/fees", response_class=HTMLResponse)
def fees_page(request: Request):
    if not auth.current_session(request):
        return _login_redirect(request)
    return render("fees", "Fees", request, scripts='<script src="/static/fees.js" defer></script>')


@router.get("/fees/receipt", response_class=HTMLResponse)
def receipt_page(request: Request):
    if not auth.current_session(request):
        return _login_redirect(request)
    return render("receipt", "Fee receipt", request, scripts='<script src="/static/receipt.js" defer></script>')


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request):
    if not auth.current_session(request):
        return _login_redirect(request)
    return render("account", "Account security", request, scripts='<script src="/static/account.js" defer></script>')


@router.get("/logout")
def logout_page(request: Request):
    token = request.cookies.get(auth.SESSION_COOKIE)
    if token:
        auth.end_session(token)
    resp = RedirectResponse("/?bye=1", status_code=303)
    resp.delete_cookie(auth.SESSION_COOKIE)
    return resp


# ====================================================================== auth API
async def _json(request: Request) -> dict:
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def _norm_dob(raw: str) -> str:
    raw = (raw or "").strip()
    if len(raw) == 10 and raw[4] == "-":            # YYYY-MM-DD from a date picker
        y, m, d = raw.split("-")
        return f"{d}{m}{y}"
    return raw.replace("/", "").replace("-", "")


@router.post("/api/auth/step1")
async def auth_step1(request: Request):
    data = await _json(request)
    roll = str(data.get("roll", "")).strip()
    dob = _norm_dob(str(data.get("dob", "")))
    left = auth.usn_locked(roll)
    if left:
        return JSONResponse({"error": f"This USN is locked after too many wrong attempts. Try again in {int(left // 60) + 1} min.",
                             "locked": True, "seconds_left": int(left)}, status_code=423)
    with db.connect() as conn:
        # WEAK SPOT #5a: the "password" is the date of birth (DDMMYYYY), stored
        # in plain text. Anyone who knows a classmate's birthday can pass step 1.
        # SAFE VERSION: row = conn.execute("SELECT password_hash FROM students WHERE roll=?", (roll,))
        #               ok = argon2.verify(row["password_hash"], password)  # a real, user-chosen password
        row = conn.execute("SELECT roll, name FROM students WHERE roll = ? AND password = ?", (roll, dob)).fetchone()
    if not row:
        return JSONResponse({"error": "Invalid USN or date of birth."}, status_code=401)
    token = secrets.token_urlsafe(16)
    auth.PENDING[token] = {"roll": roll}
    parts = row["name"].split()
    hint = " ".join(p[0] + "•" * (len(p) - 1) for p in parts)
    resp = JSONResponse({"ok": True, "step": 2, "name_hint": hint})
    resp.set_cookie(auth.PENDING_COOKIE, token, httponly=True, samesite="lax")
    return resp


@router.post("/api/auth/step2")
async def auth_step2(request: Request):
    data = await _json(request)
    pending = auth.PENDING.get(request.cookies.get(auth.PENDING_COOKIE, ""))
    if not pending:
        return JSONResponse({"error": "Start again: enter your USN and date of birth first."}, status_code=400)
    roll = pending["roll"]
    left = auth.usn_locked(roll)
    if left:
        return JSONResponse({"error": f"This USN is locked after too many wrong attempts. Try again in {int(left // 60) + 1} min.",
                             "locked": True, "seconds_left": int(left)}, status_code=423)
    id_card = str(data.get("id_card", "")).strip().upper()
    with db.connect() as conn:
        # WEAK SPOT #5b: the "second factor" is the ID-card number, which is
        # printed on a card students show all day. It is not a secret.
        # SAFE VERSION: send a one-time code to the registered phone / authenticator app
        #               and compare with hmac.compare_digest(expected_otp, submitted_otp)
        row = conn.execute("SELECT name FROM students WHERE roll = ? AND id_card = ?", (roll, id_card)).fetchone()
    if not row:
        n = auth.record_id_card_failure(roll)
        left_tries = max(0, auth.USN_LOCK_AFTER - n)
        msg = "Wrong ID card number." + (f" {left_tries} attempts left before this USN is locked." if left_tries else
                                         " This USN is now locked for 5 minutes.")
        return JSONResponse({"error": msg, "attempts_left": left_tries}, status_code=401)
    auth.clear_usn_failures(roll)
    auth.PENDING.pop(request.cookies.get(auth.PENDING_COOKIE, ""), None)
    s = auth.create_session(roll, request)
    resp = JSONResponse({"ok": True, "roll": roll, "name": row["name"]})
    resp.set_cookie(auth.SESSION_COOKIE, s.token, httponly=True, samesite="lax")
    resp.delete_cookie(auth.PENDING_COOKIE)
    return resp


@router.post("/api/auth/logout")
def auth_logout(request: Request):
    token = request.cookies.get(auth.SESSION_COOKIE)
    if token:
        auth.end_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.SESSION_COOKIE)
    return resp


@router.post("/api/auth/logout-all")
def auth_logout_all(request: Request):
    s = auth.current_session(request)
    if not s:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    n = auth.end_all_sessions(s.roll)
    resp = JSONResponse({"ok": True, "ended": n})
    resp.delete_cookie(auth.SESSION_COOKIE)
    return resp


@router.get("/api/me")
def me(request: Request):
    s = auth.current_session(request)
    if not s:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    with db.connect() as conn:
        row = conn.execute("SELECT roll, name, branch, email FROM students WHERE roll = ?", (s.roll,)).fetchone()
    return {**dict(row), "branch_name": db.BRANCHES.get(row["branch"], row["branch"]),
            "trusted_device": s.trusted, "active_sessions": len(auth.sessions_for(s.roll))}


@router.get("/api/stats")
def stats():
    return db.counts()


# ====================================================================== data APIs
def _need_session(request: Request):
    s = auth.current_session(request)
    if not s:
        return None, JSONResponse({"error": "Please log in."}, status_code=401)
    return s, None


@router.get("/api/results")
def api_results(request: Request, roll: str | None = None):
    s, err = _need_session(request)
    if err:
        return err
    # WEAK SPOT #1 (IDOR): the roll number comes straight from the URL and is
    # never compared with the logged-in student. Change ?roll=101 to ?roll=102
    # and you get someone else's marks.
    # SAFE VERSION: roll = s.roll          # ignore the URL; always use the session's own roll
    #               (or: if roll and roll != s.roll: return JSONResponse({...}, status_code=403))
    roll = roll or s.roll
    with db.connect() as conn:
        st = conn.execute("SELECT roll, name, branch FROM students WHERE roll = ?", (roll,)).fetchone()
        if not st:
            return JSONResponse({"error": "No such student."}, status_code=404)
        rows = conn.execute("SELECT semester, sgpa, marks FROM results WHERE roll = ? ORDER BY semester", (roll,)).fetchall()
    sems = [{"semester": r["semester"], "sgpa": r["sgpa"], "marks": json.loads(r["marks"])} for r in rows]
    cgpa = round(sum(x["sgpa"] for x in sems) / len(sems), 2) if sems else None
    return {"roll": st["roll"], "name": st["name"], "branch": st["branch"],
            "branch_name": db.BRANCHES.get(st["branch"]), "cgpa": cgpa, "semesters": sems}


@router.get("/api/library/borrowers")
def api_library_borrowers(limit: int | None = None):
    with db.connect() as conn:
        # WEAK SPOT #2 (over-exposure): SELECT * sends phone, Aadhaar and home
        # address of every borrower to the browser. The page only *displays*
        # name, book and due date, but the data has already left the server.
        # There is also no cap on ?limit=, so one call can dump the whole table.
        # SAFE VERSION: limit = min(limit or 20, 50)
        #               conn.execute("SELECT id, book, due FROM library ORDER BY due LIMIT ?", (limit,))
        sql = "SELECT * FROM library ORDER BY due"
        rows = conn.execute(sql + " LIMIT ?", (limit,)).fetchall() if limit else conn.execute(sql).fetchall()
    return {"count": len(rows), "rows": [dict(r) for r in rows]}


@router.get("/api/library/mine")
def api_library_mine(request: Request):
    s, err = _need_session(request)
    if err:
        return err
    with db.connect() as conn:
        rows = conn.execute("SELECT id, book, due FROM library WHERE roll = ? ORDER BY due", (s.roll,)).fetchall()
    return {"rows": [dict(r) for r in rows]}


@router.get("/api/admissions/search")
def api_admissions_search(q: str = ""):
    q = q.strip()
    if not q:
        return {"count": 0, "rows": []}
    # WEAK SPOT #3 (SQL injection): the search text is pasted into the SQL
    # string. Searching for   x' OR '1'='1   turns the WHERE clause into
    # "always true" and returns every applicant with phone and email.
    # SAFE VERSION: conn.execute("SELECT id, name, branch, status FROM applicants "
    #                            "WHERE name = ? OR name LIKE ? OR name LIKE ? LIMIT 25",
    #                            (q, q + " %", "% " + q))
    sql = (f"SELECT * FROM applicants WHERE name = '{q}' "
           f"OR name LIKE '{q} %' OR name LIKE '% {q}'")
    try:
        with db.connect() as conn:
            rows = conn.execute(sql).fetchall()
    except sqlite3.Error as e:
        # WEAK SPOT #3b: raw database errors are echoed to the client, which
        # helps an attacker shape the injection.
        # SAFE VERSION: log the error server-side; return {"error": "Search failed."}
        return JSONResponse({"error": "Database error", "detail": str(e)}, status_code=500)
    return {"count": len(rows), "rows": [dict(r) for r in rows]}


@router.get("/api/fees")
def api_fees(request: Request):
    s, err = _need_session(request)
    if err:
        return err
    with db.connect() as conn:
        rows = conn.execute("SELECT challan_no, amount, mode, date, receipt_no FROM fees WHERE roll = ? ORDER BY date DESC",
                            (s.roll,)).fetchall()
    return {"roll": s.roll, "rows": [dict(r) for r in rows]}


@router.get("/api/fees/receipt")
def api_fee_receipt(request: Request, userId: str = "", challan: str = ""):
    s, err = _need_session(request)
    if err:
        return err
    with db.connect() as conn:
        # WEAK SPOT #4 (IDOR on fee receipts): the receipt is fetched by the
        # userId in the URL, with no check that it belongs to the logged-in
        # student. And SELECT * on the join also returns Aadhaar, address and
        # even the plain-text password.
        # SAFE VERSION: conn.execute("SELECT f.challan_no, f.amount, f.mode, f.date, f.receipt_no, s.name, s.branch "
        #                            "FROM fees f JOIN students s ON s.roll = f.roll "
        #                            "WHERE f.roll = ? AND f.challan_no = ?", (s.roll, challan))
        sql = "SELECT * FROM fees f JOIN students s ON s.roll = f.roll WHERE f.roll = ?"
        args: tuple = (userId or s.roll,)
        if challan:
            sql += " AND f.challan_no = ?"
            args += (challan,)
        row = conn.execute(sql + " ORDER BY f.date DESC LIMIT 1", args).fetchone()
    if not row:
        return JSONResponse({"error": "Receipt not found."}, status_code=404)
    out = dict(row)
    out["userId"] = out.pop("roll")
    out["branch_name"] = db.BRANCHES.get(out["branch"])
    return out


@router.get("/api/fees/receipt/download")
def api_fee_receipt_download(request: Request, userId: str = "", challan: str = ""):
    """'Generate receipt' button: the receipt as a PDF file, downloaded straight away."""
    s, err = _need_session(request)
    if err:
        return err
    with db.connect() as conn:
        # WEAK SPOT #4 again (IDOR): the owner comes from ?userId= in the URL.
        # WEAK SPOT #4b (portable link): this is a plain GET link. Dragged or pasted
        # into any other tab, it downloads the receipt there too, and anyone who
        # gets the URL plus a session can fetch it.
        # SAFE VERSION: owner = s.roll, and only serve the file to the page that asked
        #               for it, e.g. against a one-time, session-bound download ticket.
        row = conn.execute("SELECT f.challan_no, f.amount, f.mode, f.date, f.receipt_no, s.name, s.branch, s.roll "
                           "FROM fees f JOIN students s ON s.roll = f.roll WHERE f.roll = ? AND f.challan_no = ?",
                           (userId or s.roll, challan)).fetchone()
    if not row:
        return JSONResponse({"error": "Receipt not found."}, status_code=404)
    d = dict(row)
    d["userId"] = d.pop("roll")
    d["branch_name"] = db.BRANCHES.get(d["branch"])
    safe = "".join(ch for ch in d["challan_no"] if ch.isalnum())
    return Response(pdf.fee_receipt(d), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="receipt-{safe}.pdf"',
                             "Cache-Control": "no-store"})



# ---------------------------------------------------------------- course registration acknowledgement
def _ack_data(roll: str) -> dict | None:
    with db.connect() as conn:
        st = conn.execute("SELECT roll, name, branch FROM students WHERE roll = ?", (roll,)).fetchone()
    if not st:
        return None
    groups: dict[str, list] = {}
    for category, code, name, credits in db.COURSES:
        groups.setdefault(category, []).append((code, name, credits))
    digest = hashlib.sha256(f"{st['roll']}|{db.REGISTRATION['term']}".encode()).hexdigest()[:6].upper()
    return {
        "name": st["name"], "userId": st["roll"], "branch_name": db.BRANCHES.get(st["branch"], st["branch"]),
        "semester": db.REGISTRATION["semester"], "term": db.REGISTRATION["term"], "stream": db.REGISTRATION["stream"],
        "groups": list(groups.items()), "count": len(db.COURSES), "total": sum(c[3] for c in db.COURSES),
        "ack_no": f"ACK-{db.REGISTRATION['semester']}-{st['roll']}-{digest}",
        "generated": time.strftime("%d %b %Y"),
    }


@router.get("/api/acknowledgement")
def api_acknowledgement(request: Request):
    """The logged-in student's own registration, for the on-page preview."""
    s, err = _need_session(request)
    if err:
        return err
    d = _ack_data(s.roll)
    if not d:
        return JSONResponse({"error": "Student not found."}, status_code=404)
    d["groups"] = [{"category": c, "courses": [{"code": a, "name": b, "credits": x} for a, b, x in rows]}
                   for c, rows in d["groups"]]
    return d


@router.get("/api/acknowledgement/download")
def api_acknowledgement_download(request: Request, userId: str = "", sem: str = ""):
    """'Download acknowledgement' button: the acknowledgement as a PDF file, straight away."""
    s, err = _need_session(request)
    if err:
        return err
    # WEAK SPOT #6 (IDOR + portable link): the student comes from ?userId= in the URL,
    # and it is a plain GET link, so dragged or pasted into any tab it downloads there too.
    # SAFE VERSION: d = _ack_data(s.roll), and only serve the file to the page that asked
    #               for it, against a one-time, session-bound download ticket.
    d = _ack_data(userId or s.roll)
    if not d:
        return JSONResponse({"error": "Acknowledgement not found."}, status_code=404)
    return Response(pdf.course_acknowledgement(d), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="acknowledgement-sem{d["semester"]}-{d["userId"]}.pdf"',
                             "Cache-Control": "no-store"})
