#!/usr/bin/env python3
"""Kavach attack simulator: LOCALHOST ONLY.

Runs each demo attack against the fictional Northfield portal so the
difference between Agent OFF and Agent ON is obvious. Every attack uses its
own fake attacker IP (X-Forwarded-For) so blocking one does not hide the next.

    python attacks/simulate.py all              # run everything against the current agent state
    python attacks/simulate.py all --compare    # run with the agent OFF, then ON, side by side
    python attacks/simulate.py scrape           # one attack: scrape | overexposure | sqli | receipt |
                                                #              lockout | bruteforce | hijack

    Availability scenarios (not part of "all"):
    python attacks/simulate.py flood --compare  # a bot flood while a real student uses Results
    python attacks/simulate.py rush --compare   # results day: 300 real students at once while one pays fees

The simulator refuses to target anything except 127.0.0.1 / localhost.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import random
import socket
import sqlite3
import statistics
import sys
import time
from contextlib import closing
from pathlib import Path
from datetime import date, timedelta
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    sys.exit("httpx is required: pip install -r requirements.txt")

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}

# Demo accounts (fictional). Keep in sync with STORY_ACCOUNTS in app/db.py.
ACCOUNTS = {
    "101": {"name": "Rahul Sharma", "dob": "05032004", "id_card": "NITM240101"},   # the curious scraper
    "102": {"name": "Priya Rao", "dob": "14082004", "id_card": "NITM240102"},      # lockout victim
    "103": {"name": "Kavya Nair", "dob": "21062004", "id_card": "NITM240103"},     # DOB-guessing + hijack victim
    "104": {"name": "Arjun Mehta", "dob": "02112004", "id_card": "NITM240104"},    # receipt snooper
    "105": {"name": "Sneha Patil", "dob": "19012005", "id_card": "NITM240105"},    # classmate on the same Wi-Fi
}
ATTACKER_IPS = {
    "scrape": "10.66.0.11", "overexposure": "10.66.0.12", "sqli": "10.66.0.13", "receipt": "10.66.0.14",
    "lockout": "10.66.0.15", "bruteforce": "10.66.0.16", "hijack": "10.30.1.7",
}

# ------------------------------------------------------------------ output helpers
if os.name == "nt":
    os.system("")                                  # enable ANSI colours in the Windows console
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass
USE_COLOUR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOUR else text


RED, GREEN, AMBER, DIM, BOLD, CYAN = "91", "92", "93", "2", "1", "96"


def bad(msg: str) -> None:
    print("   " + c("✖ " + msg, RED))


def good(msg: str) -> None:
    print("   " + c("✔ " + msg, GREEN))


def warn(msg: str) -> None:
    print("   " + c("▲ " + msg, AMBER))


def info(msg: str) -> None:
    print("   " + c("· " + msg, DIM))


def header(name: str, about: str) -> None:
    print()
    print(c(f"▶ {name}", BOLD + ";" + CYAN) + c(f"  {about}", DIM))


# ------------------------------------------------------------------ safety guard
def guard_target(url: str) -> str:
    """Exit unless the target is this machine. Checks the name AND what it resolves to."""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if p.scheme not in ("http", "https") or host not in ALLOWED_HOSTS:
        sys.exit(f"REFUSED: the simulator only attacks 127.0.0.1 / localhost (got '{host or url}').")
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, p.port or 80)}
    except socket.gaierror:
        sys.exit(f"REFUSED: cannot resolve '{host}'.")
    if not addrs or not all(ipaddress.ip_address(a.split("%")[0]).is_loopback for a in addrs):
        sys.exit(f"REFUSED: '{host}' resolves to a non-loopback address {sorted(addrs)}.")
    return f"{p.scheme}://{host if ':' not in host else '[' + host + ']'}:{p.port or 80}"


# ------------------------------------------------------------------ client
class Client:
    """One browser: its own cookie jar (so its own Kavach device ID) and its own IP."""

    def __init__(self, base: str, ip: str, label: str):
        self.ip = ip
        self.http = httpx.Client(base_url=base, timeout=15, follow_redirects=False, headers={
            "X-Forwarded-For": ip, "User-Agent": f"kavach-simulator/{label}", "Accept": "application/json"})

    def get(self, path: str, **kw) -> httpx.Response:
        return self.http.get(path, **kw)

    def post(self, path: str, json: dict | None = None) -> httpx.Response:
        return self.http.post(path, json=json or {})

    def login(self, roll: str, id_card: str | None = None) -> httpx.Response:
        a = ACCOUNTS[roll]
        r = self.post("/api/auth/step1", {"roll": roll, "dob": a["dob"]})
        if r.status_code != 200:
            return r
        return self.post("/api/auth/step2", {"id_card": id_card or a["id_card"]})

    def close(self) -> None:
        self.http.close()


def jget(r: httpx.Response) -> dict:
    try:
        d = r.json()
        return d if isinstance(d, dict) else {"_": d}
    except ValueError:
        return {}


def blocked_by_kavach(r: httpx.Response) -> bool:
    return r.status_code == 403 and jget(r).get("by") == "Kavach"


def why(r: httpx.Response) -> str:
    d = jget(r)
    return f"{d.get('reason') or d.get('error')} [{d.get('incident') or d.get('kavach') or r.status_code}]"


def looks_raw_phone(v) -> bool:
    return isinstance(v, str) and v.isdigit() and len(v) == 10


# ================================================================== attacks
def attack_scrape(base: str, n: int = 300) -> dict:
    header("scrape", f"log in as roll 101, walk ?roll= across {n} other students (WEAK SPOT #1)")
    cl = Client(base, ATTACKER_IPS["scrape"], "scrape")
    r = cl.login("101")
    if r.status_code != 200:
        bad(f"could not log in as 101: {why(r)}")
        return {"attack": "scrape", "leaked": 0, "blocked": blocked_by_kavach(r), "note": "login failed"}
    info("logged in as Rahul Sharma (101)")
    stolen, blocked, sample, stop = 0, False, None, ""
    for roll in range(102, 102 + n):
        r = cl.get("/api/results", params={"roll": roll})
        if r.status_code == 200:
            stolen += 1
            sample = sample or jget(r)
        elif blocked_by_kavach(r) or r.status_code == 401:
            blocked, stop = True, why(r)
            break
    cl.close()
    if sample:
        info(f"e.g. {sample['name']} ({sample['roll']}): CGPA {sample.get('cgpa')}, "
             f"sem-4 SGPA {sample['semesters'][-1]['sgpa'] if sample.get('semesters') else '?'}")
    if blocked:
        warn(f"{stolen} records got out before the pattern crossed the limit (all logged in the leak ledger)")
        good(f"then blocked: {stop}")
    else:
        bad(f"{stolen} other students' results stolen")
    return {"attack": "scrape", "leaked": stolen, "blocked": blocked}


def attack_overexposure(base: str) -> dict:
    header("overexposure", "call the library API directly; the page hides phone/Aadhaar/address, the API doesn't (WEAK SPOT #2)")
    cl = Client(base, ATTACKER_IPS["overexposure"], "overexposure")
    r = cl.get("/api/library/borrowers", params={"limit": 25})
    rows = jget(r).get("rows", [])
    raw = [x for x in rows if looks_raw_phone(x.get("phone"))]
    if rows:
        x = rows[0]
        info(f"row 1 → {x.get('student_name')}: phone {x.get('phone')}, aadhaar {x.get('aadhaar')}, address {str(x.get('address'))[:38]}")
    if raw:
        bad(f"{len(raw)}/{len(rows)} borrowers' phone, Aadhaar and address exposed in one page of 25")
    else:
        good(f"{len(rows)} rows came back with phone/Aadhaar/address masked by Kavach")
    r2 = cl.get("/api/library/borrowers")          # no ?limit= at all: the whole table
    rows2 = jget(r2).get("rows", [])
    raw2 = [x for x in rows2 if looks_raw_phone(x.get("phone"))]
    if blocked_by_kavach(r2):
        good(f"full-table dump stopped: {why(r2)}")
    elif raw2:
        bad(f"full-table dump: {len(raw2)} borrowers with raw personal data")
    cl.close()
    return {"attack": "overexposure", "leaked": max(len(raw), len(raw2)), "blocked": blocked_by_kavach(r2)}


def attack_sqli(base: str) -> dict:
    header("sqli", "search admissions for  x' OR '1'='1  to dump every applicant (WEAK SPOT #3)")
    cl = Client(base, ATTACKER_IPS["sqli"], "sqli")
    r = cl.get("/api/admissions/search", params={"q": "x' OR '1'='1"})
    rows = jget(r).get("rows", [])
    cl.close()
    if blocked_by_kavach(r):
        good(f"blocked before the database: {why(r)}")
        return {"attack": "sqli", "leaked": 0, "blocked": True}
    raw = [x for x in rows if looks_raw_phone(x.get("phone"))]
    if rows:
        x = rows[0]
        info(f"row 1 → {x.get('name')}: {x.get('email')}, {x.get('phone')}, PUC {x.get('puc_marks')}")
    (bad if raw else good)(f"{len(rows)} applicants dumped ({len(raw)} with raw phone + email)")
    return {"attack": "sqli", "leaked": len(raw), "blocked": False}


def attack_receipt(base: str, n: int = 20) -> dict:
    header("receipt", "log in as 104, change userId on the fee-receipt link (WEAK SPOT #4, the real-world flaw)")
    cl = Client(base, ATTACKER_IPS["receipt"], "receipt")
    r = cl.login("104")
    if r.status_code != 200:
        bad(f"could not log in as 104: {why(r)}")
        return {"attack": "receipt", "leaked": 0, "blocked": blocked_by_kavach(r), "note": "login failed"}
    own = jget(cl.get("/api/fees")).get("rows", [])
    info(f"logged in as Arjun Mehta (104), who has {len(own)} receipts of his own")
    stolen, refused, sample, last = 0, 0, None, None
    for uid in [u for u in range(101, 101 + n + 1) if u != 104][:n]:
        r = cl.get("/api/fees/receipt", params={"userId": uid})
        if r.status_code == 200:
            stolen += 1
            sample = sample or jget(r)
        elif r.status_code == 403:
            refused += 1
            last = r
    cl.close()
    if sample:
        info(f"e.g. {sample.get('name')} ({sample.get('userId')}): ₹{sample.get('amount')} · phone {sample.get('phone')} · "
             f"aadhaar {sample.get('aadhaar')} · password {sample.get('password')}")
    (bad if stolen else good)(f"{stolen} other students' fee receipts read")
    if refused:
        good(f"{refused} receipt requests refused: {why(last)}")
    return {"attack": "receipt", "leaked": stolen, "blocked": refused > 0}


def attack_lockout(base: str, tries: int = 12) -> dict:
    header("lockout", "brute-force ID-card numbers for Priya Rao (102), then see if the real Priya can log in (WEAK SPOT #5)")
    atk = Client(base, ATTACKER_IPS["lockout"], "lockout")
    r = atk.post("/api/auth/step1", {"roll": "102", "dob": ACCOUNTS["102"]["dob"]})
    info(f"attacker at {atk.ip} knows Priya's birthday → step 1: HTTP {r.status_code}")
    sent, blocked_at = 0, None
    for i in range(tries):
        r = atk.post("/api/auth/step2", {"id_card": f"NITM{(314159 + 7919 * i) % 1000000:06d}"})
        sent += 1
        if blocked_by_kavach(r):
            blocked_at = i + 1
            break
    atk.close()
    if blocked_at:
        good(f"attacker blocked on try {blocked_at} ({blocked_at - 1} wrong guesses reached the portal): {why(r)}")
    else:
        bad(f"attacker sent {sent} wrong ID-card numbers unopposed (last reply: HTTP {r.status_code})")

    mate = Client(base, ATTACKER_IPS["lockout"], "classmate")     # same campus Wi-Fi IP, different device
    rm = mate.login("105")
    mate.close()
    if rm.status_code == 200:
        good("classmate Sneha (105) on the SAME Wi-Fi IP but her own device logs in fine")
    else:
        bad(f"classmate on the same IP could not log in: {why(rm)}")

    real = Client(base, "10.20.4.102", "real-priya")                # the real student, her own phone
    rr = real.login("102")
    real.close()
    if rr.status_code == 200:
        good("the REAL Priya logs in normally: her account was never locked")
        locked = False
    else:
        bad(f"the REAL Priya is locked out of her own account: {why(rr)}")
        locked = True
    return {"attack": "lockout", "leaked": 0, "blocked": bool(blocked_at), "victim_locked_out": locked}


def attack_bruteforce(base: str) -> dict:
    header("bruteforce", "guess Kavya Nair's (103) password by trying every date of birth in 2004 (WEAK SPOT #5)")
    cl = Client(base, ATTACKER_IPS["bruteforce"], "bruteforce")
    d, tries, cracked, blocked = date(2004, 1, 1), 0, None, None
    while d.year == 2004:
        guess = d.strftime("%d%m%Y")
        r = cl.post("/api/auth/step1", {"roll": "103", "dob": guess})
        tries += 1
        if r.status_code == 200:
            cracked = guess
            break
        if blocked_by_kavach(r):
            blocked = r
            break
        d += timedelta(days=1)
    cl.close()
    if cracked:
        bad(f"password cracked after {tries} guesses: {cracked} (her date of birth)")
    if blocked is not None:
        good(f"blocked after {tries - 1} wrong guesses: {why(blocked)}")
    return {"attack": "bruteforce", "leaked": 1 if cracked else 0, "blocked": blocked is not None}


def attack_hijack(base: str) -> dict:
    header("hijack", "Kavya logs in on a lab PC; someone replays her session cookie from another device")
    victim = Client(base, ATTACKER_IPS["hijack"], "lab-pc")
    r = victim.login("103")
    if r.status_code != 200:
        bad(f"victim could not log in: {why(r)}")
        return {"attack": "hijack", "leaked": 0, "blocked": False, "note": "login failed"}
    token = victim.http.cookies.get("nitm_session")
    info(f"Kavya logged in on the lab PC ({victim.ip}); the attacker copies her session cookie")
    thief = Client(base, ATTACKER_IPS["hijack"], "thief")            # same lab network, different machine
    thief.http.cookies.set("nitm_session", token)
    r = thief.get("/api/results")
    victim.close()
    thief.close()
    if r.status_code == 200:
        d = jget(r)
        bad(f"attacker is inside Kavya's account: sees {d.get('name')}'s CGPA {d.get('cgpa')}")
        return {"attack": "hijack", "leaked": 1, "blocked": False}
    good(f"replayed cookie rejected: {why(r)}")
    return {"attack": "hijack", "leaked": 0, "blocked": True}


ATTACKS = {
    "scrape": attack_scrape, "overexposure": attack_overexposure, "sqli": attack_sqli, "receipt": attack_receipt,
    "lockout": attack_lockout, "bruteforce": attack_bruteforce, "hijack": attack_hijack,
}


# ================================================================== availability scenarios (not in "all")
# Bounded, localhost-only load tests for the availability shield (agent/availability.py).
FLOOD_BOTS, FLOOD_CONNECTIONS, FLOOD_SECONDS, FLOOD_MAX = 4, 16, 30, 60000
# Demo server for each scenario: the flood uses a small, busy college server (2 workers, 250 ms database),
# the rush a mid-size one (the defaults: 8 workers, 100 ms).
SERVER_PROFILE = {"flood": {"workers": 2, "db_ms": 250}, "rush": {}}
RUSH_STUDENTS, RUSH_SECONDS = int(os.environ.get("RUSH_STUDENTS", 300)), 18
FEE_STUDENT_IP, RESULTS_STUDENT_IP = "10.88.0.5", "10.88.0.6"


def _students(n: int) -> list[tuple[str, str, str]]:
    """(roll, password, id_card) of n fictional students from the local portal database."""
    path = Path(__file__).resolve().parent.parent / "data" / "portal.db"
    if not path.exists():
        sys.exit("data/portal.db not found: start the portal once first (python run.py)")
    with closing(sqlite3.connect(path)) as conn:
        return conn.execute("SELECT roll, password, id_card FROM students WHERE CAST(roll AS INTEGER) > 105 "
                            "ORDER BY CAST(roll AS INTEGER) LIMIT ?", (n,)).fetchall()


def _aclient(base: str, ip: str, label: str) -> "httpx.AsyncClient":
    return httpx.AsyncClient(base_url=base, timeout=10, follow_redirects=False, headers={
        "X-Forwarded-For": ip, "User-Agent": f"kavach-simulator/{label}", "Accept": "application/json"})


async def _alogin(cl, roll: str, password: str, id_card: str) -> bool:
    try:
        r = await cl.post("/api/auth/step1", json={"roll": roll, "dob": password})
        if r.status_code != 200:
            return False
        return (await cl.post("/api/auth/step2", json={"id_card": id_card})).status_code == 200
    except httpx.HTTPError:
        return False


def _fmt_ms(v) -> str:
    if v is None:
        return "-"
    return f"{v / 1000:.1f} s" if v >= 1000 else f"{v:.0f} ms"


def _median(values: list[float]):
    return statistics.median(values) if values else None


async def _pay_fees(base: str, stop: asyncio.Event, samples: list) -> None:
    """A real student (Sneha, 105) opening Fees and downloading a receipt, every second."""
    a = ACCOUNTS["105"]
    async with _aclient(base, FEE_STUDENT_IP, "fee-student") as cl:
        await _alogin(cl, "105", a["dob"], a["id_card"])
        while not stop.is_set():
            t0, ok = time.perf_counter(), False
            try:
                r = await cl.get("/api/fees")
                if r.status_code == 200 and r.json().get("rows"):
                    ch = r.json()["rows"][0]["challan_no"]
                    t = jget(await cl.post("/kavach/ticket", json={"kind": "receipt", "userId": "105", "ref": ch})).get("ticket")
                    r2 = await cl.get(f"/api/fees/receipt/download?userId=105&challan={ch}",
                                      headers={"X-Kavach-Ticket": t} if t else {})
                    ok = r2.status_code == 200 and r2.content[:5] == b"%PDF-"
            except httpx.HTTPError:
                ok = False
            samples.append(((time.perf_counter() - t0) * 1000, ok))
            await asyncio.sleep(1.0)


def _flood(base: str) -> dict:
    """Bots run in threads: one Python process juggling many asyncio connections stalls on
    Windows long before the server does, so threads give a realistic flood."""
    import threading
    st = {"sent": 0, "refused": 0, "served": 0, "timeouts": 0}
    lock = threading.Lock()
    a = ACCOUNTS["105"]

    def watch(stop: threading.Event, samples: list) -> None:
        """Opens the whole Results page like a browser: the page, then its data."""
        cl = Client(base, RESULTS_STUDENT_IP, "real-student")
        cl.http.timeout = httpx.Timeout(40)
        try:
            cl.login("105")
            while not stop.is_set():
                t0 = time.perf_counter()
                try:
                    ok = (cl.get("/results", headers={"Accept": "text/html"}).status_code == 200
                          and cl.get("/api/results").status_code == 200)
                except httpx.HTTPError:
                    ok = False
                samples.append(((time.perf_counter() - t0) * 1000, ok))
                stop.wait(0.5)
        finally:
            cl.close()

    def bot(ip: str, stop: threading.Event) -> None:
        cl = Client(base, ip, "flood-bot")
        cl.http.timeout = httpx.Timeout(10)
        paths, i = ["/api/stats", "/api/admissions/search?q=an", "/"], 0      # database-heavy pages
        try:
            while not stop.is_set() and st["sent"] < FLOOD_MAX:
                cl.http.cookies.clear()                 # a bot that drops cookies
                try:
                    r = cl.get(paths[i % 3])
                except httpx.HTTPError:
                    with lock:
                        st["timeouts"] += 1
                    continue
                i += 1
                with lock:
                    st["sent"] += 1
                    st["refused" if r.status_code in (403, 429) else "served"] += 1
        finally:
            cl.close()

    before, during = [], []
    stop = threading.Event()
    w = threading.Thread(target=watch, args=(stop, before), daemon=True)
    w.start()
    time.sleep(3)                                       # the student's normal experience
    stop.set()
    w.join()

    stop = threading.Event()
    ips = [f"10.99.0.{i + 10}" for i in range(FLOOD_BOTS)]
    threads = [threading.Thread(target=bot, args=(ip, stop), daemon=True) for ip in ips for _ in range(FLOOD_CONNECTIONS)]
    threads.append(threading.Thread(target=watch, args=(stop, during), daemon=True))
    t0 = time.time()
    for t in threads:
        t.start()
    while time.time() - t0 < FLOOD_SECONDS and st["sent"] < FLOOD_MAX:
        time.sleep(0.25)
    stop.set()
    for t in threads:
        t.join(timeout=15)
    return {"st": st, "before": before, "during": during, "secs": time.time() - t0, "bots": len(ips)}


def attack_flood(base: str) -> dict:
    header("flood", f"{FLOOD_BOTS} bot machines flood the portal for {FLOOD_SECONDS} s while a real student keeps opening Results")
    r = _flood(base)
    st, during = r["st"], r["during"]
    ok = [ms for ms, g in during if g]
    failed = sum(1 for _, g in during if not g)
    info(f"real student before the flood: the Results page opens in {_fmt_ms(_median([m for m, g in r['before'] if g]))}")
    info(f"{st['sent']} bot requests in {r['secs']:.0f} s ({st['sent'] / r['secs']:.0f}/s) from {r['bots']} IPs")
    (good if st["refused"] else bad)(f"{st['refused']} bot requests refused by Kavach, {st['served']} served")
    (good if not failed and ok and _median(ok) < 1000 else warn)(
        f"real student during the flood: the Results page opens in {_fmt_ms(_median(ok))} (median), slowest "
        f"{_fmt_ms(max(ok) if ok else None)}, {failed} of {len(during)} failed")
    return {"attack": "flood", "leaked": 0, "blocked": st["refused"] > 0, "student_ms": _median(ok),
            "student_max": max(ok) if ok else None, "student_failed": failed, "student_tries": len(during),
            "bot_served": st["served"], "bot_refused": st["refused"]}


async def _rush(base: str) -> dict:
    students = _students(RUSH_STUDENTS)
    st = {"ok": 0, "queued": 0, "errors": 0, "timeouts": 0, "first_ms": [], "never": 0, "login_failed": 0}
    go, stop, samples = asyncio.Event(), asyncio.Event(), []
    logged_in = asyncio.Semaphore(15)
    ready = []

    async def student(i: int, roll: str, pw: str, card: str) -> None:
        async with _aclient(base, f"10.77.{i // 200}.{i % 200 + 20}", "results-student") as cl:
            async with logged_in:
                ok = await _alogin(cl, roll, pw, card)
            ready.append(ok)
            if not ok:
                st["login_failed"] += 1
                return
            await go.wait()                             # results are published: everyone at once
            t_first, got = time.perf_counter(), False
            while not stop.is_set():
                try:
                    r = await cl.get("/api/results")
                except httpx.HTTPError:
                    st["timeouts"] += 1
                    await asyncio.sleep(0.5)
                    continue
                if r.status_code == 200:
                    if not got:
                        got = True
                        st["first_ms"].append((time.perf_counter() - t_first) * 1000)
                    st["ok"] += 1
                    await asyncio.sleep(random.uniform(0.3, 0.8))       # impatient refreshing
                elif r.status_code == 503 and jget(r).get("queued"):
                    st["queued"] += 1                   # "you're number N in line": wait as told
                    await asyncio.sleep(jget(r).get("retry_ms", 1000) / 1000)
                else:
                    st["errors"] += 1
                    await asyncio.sleep(0.5)
            if not got:
                st["never"] += 1

    crowd = [asyncio.create_task(student(i, *s)) for i, s in enumerate(students)]
    while len(ready) < len(students):                   # wait until everyone has logged in
        await asyncio.sleep(0.2)
    payer = asyncio.create_task(_pay_fees(base, stop, samples))
    await asyncio.sleep(4)                              # fee payment on a normal day
    t_go = len(samples)
    go.set()
    await asyncio.sleep(RUSH_SECONDS)
    stop.set()
    await asyncio.gather(payer, *crowd)
    return {"st": st, "before": samples[:t_go], "during": samples[t_go:], "n": len(students)}


def attack_rush(base: str) -> dict:
    header("rush", f"results day: {RUSH_STUDENTS} real students open their results at once while Sneha (105) pays her fees")
    r = asyncio.run(_rush(base))
    st, during = r["st"], r["during"]
    ok = [ms for ms, g in during if g]
    failed = sum(1 for _, g in during if not g)
    got = r["n"] - st["login_failed"] - st["never"]
    info(f"{r['n'] - st['login_failed']} of {r['n']} students logged in (fictional accounts)")
    info(f"fee payment on a normal day: {_fmt_ms(_median([m for m, g in r['before'] if g]))}")
    (good if got and not st["timeouts"] else warn)(
        f"{got} students got their results (first result after {_fmt_ms(_median(st['first_ms']))} median); "
        f"{st['queued']} 'please wait' replies, {st['timeouts']} timeouts, {st['errors']} errors")
    (good if not failed and ok and _median(ok) < 1000 else bad)(
        f"fee payment during the rush: {_fmt_ms(_median(ok))} (median), slowest {_fmt_ms(max(ok) if ok else None)}, "
        f"{failed} of {len(during)} failed")
    return {"attack": "rush", "leaked": 0, "blocked": False, "student_ms": _median(ok),
            "student_max": max(ok) if ok else None, "student_failed": failed, "student_tries": len(during),
            "results_got": got, "results_first": _median(st["first_ms"]), "timeouts": st["timeouts"],
            "queued": st["queued"]}


EXTRA = {"flood": attack_flood, "rush": attack_rush}


def print_extra_compare(name: str, off: dict, on: dict) -> None:
    who = "Results page opens in" if name == "flood" else "student paying fees"
    rows = [(f"{who}: median", _fmt_ms(off["student_ms"]), _fmt_ms(on["student_ms"])),
            (f"{who}: slowest", _fmt_ms(off["student_max"]), _fmt_ms(on["student_max"])),
            (f"{who}: failed", f"{off['student_failed']} of {off['student_tries']}",
             f"{on['student_failed']} of {on['student_tries']}")]
    if name == "flood":
        rows.append(("bot requests served", str(off["bot_served"]), str(on["bot_served"])))
    else:
        rows += [("students who got results", str(off["results_got"]), str(on["results_got"])),
                 ("first result (median)", _fmt_ms(off["results_first"]), _fmt_ms(on["results_first"])),
                 ("results timeouts", str(off["timeouts"]), str(on["timeouts"]))]
    print()
    print(c(f"OFF vs ON  ({name})", BOLD))
    print(f"   {'':<40}{'agent OFF':>14}{'agent ON':>14}")
    for label, a, b in rows:
        print(f"   {label:<40}{a:>14}{b:>14}")


# ================================================================== orchestration
def agent_state(base: str) -> bool | None:
    try:
        return bool(httpx.get(base + "/api/kavach/state", timeout=5).json()["enabled"])
    except Exception:
        return None


def set_agent(base: str, on: bool) -> None:
    httpx.post(base + "/api/kavach/toggle", json={"enabled": on}, timeout=5)


def reset(base: str) -> None:
    httpx.post(base + "/api/kavach/reset", timeout=5)


def run_all(base: str) -> list[dict]:
    return [fn(base) for fn in ATTACKS.values()]


def verdict(r: dict) -> str:
    if r.get("victim_locked_out"):
        return "student locked out"
    if r["leaked"] and not r["blocked"]:
        return "LEAKED"
    if r["leaked"] and r["blocked"]:
        return "contained"
    return "stopped" if r["blocked"] else "no data"


def print_summary(results: list[dict], label: str) -> None:
    print()
    print(c(f"Summary ({label})", BOLD))
    print(f"   {'attack':<14}{'records out':>12}  {'blocked':<9}verdict")
    for r in results:
        v = verdict(r)
        col = RED if v in ("LEAKED", "student locked out") else (AMBER if v == "contained" else GREEN)
        print(f"   {r['attack']:<14}{r['leaked']:>12}  {('yes' if r['blocked'] else 'no'):<9}{c(v, col)}")
    total = sum(r["leaked"] for r in results)
    print(c(f"   total records that left the server: {total}", RED if total > 20 else GREEN))


def print_compare(off: list[dict], on: list[dict]) -> None:
    print()
    print(c("OFF vs ON", BOLD))
    print(f"   {'attack':<14}{'OFF: records out':>18}  {'OFF verdict':<20}{'ON: records out':>16}  ON verdict")
    for a, b in zip(off, on):
        va, vb = verdict(a), verdict(b)
        print(f"   {a['attack']:<14}{a['leaked']:>18}  {c(f'{va:<20}', RED if va in ('LEAKED', 'student locked out') else GREEN)}"
              f"{b['leaked']:>16}  {c(vb, RED if vb in ('LEAKED', 'student locked out') else (AMBER if vb == 'contained' else GREEN))}")
    print(c(f"   total out with agent OFF: {sum(r['leaked'] for r in off)}   ·   with agent ON: {sum(r['leaked'] for r in on)}", BOLD))


def main() -> None:
    ap = argparse.ArgumentParser(description="Kavach attack simulator (localhost only)")
    ap.add_argument("attack", choices=list(ATTACKS) + ["all"] + list(EXTRA))
    ap.add_argument("--target", default="http://127.0.0.1:8000", help="portal URL (must be localhost)")
    ap.add_argument("--compare", action="store_true", help="with 'all', 'flood' or 'rush': run with the agent OFF, then ON")
    ap.add_argument("--no-reset", action="store_true", help="with 'all': don't clear the ledger / lockouts first")
    ap.add_argument("--reset", action="store_true", help="clear the ledger / lockouts before a single attack")
    ap.add_argument("--real-server", action="store_true",
                    help="flood / rush: do not switch on the demo results-day server (8 workers, slower database)")
    args = ap.parse_args()

    base = guard_target(args.target)
    state = agent_state(base)
    if state is None:
        sys.exit(f"Cannot reach the portal at {base}. Start it first:  python run.py")

    if args.attack in EXTRA:
        runs = (False, True) if args.compare else (state,)
        out = {}
        if not args.real_server:                        # behave like a real campus server for the run
            try:
                prof = httpx.post(base + "/api/kavach/demo-capacity", json={"enabled": True, **SERVER_PROFILE[args.attack]},
                                  timeout=5).json()
                info(f"results-day server ON for this run: {prof.get('workers', '?')} workers, {prof.get('db_ms', '?')} ms "
                     f"database (--real-server to skip)")
            except httpx.HTTPError:
                pass
        for on in runs:
            if args.compare:
                set_agent(base, on)
                reset(base)
            banner = "Agent OFF: no protection" if not on else "Agent ON: availability shield active"
            print("\n" + c("=" * 78, DIM) + "\n" + c(f"  {banner}", BOLD + ";" + (RED if not on else GREEN)) + "\n" + c("=" * 78, DIM))
            out[on] = EXTRA[args.attack](base)
            if args.compare and not on:
                time.sleep(3)                           # let the portal settle between runs
        if args.compare:
            print_extra_compare(args.attack, out[False], out[True])
        if not args.real_server:
            try:
                httpx.post(base + "/api/kavach/demo-capacity", json={"enabled": False}, timeout=5)
            except httpx.HTTPError:
                pass
        print(c(f"\n   Dashboard: {base}/admin", DIM))
        return

    if args.attack == "all" and args.compare:
        results = {}
        for on in (False, True):
            set_agent(base, on)
            reset(base)
            banner = "Agent OFF: requests go straight to the database" if not on else "Agent ON: Kavach inspects everything"
            print("\n" + c("═" * 78, DIM) + "\n" + c(f"  {banner}", BOLD + ";" + (RED if not on else GREEN)) + "\n" + c("═" * 78, DIM))
            results[on] = run_all(base)
        print_compare(results[False], results[True])
        print(c(f"\n   Dashboard: {base}/admin   (the agent is left ON)", DIM))
        return

    if (args.attack == "all" and not args.no_reset) or args.reset:
        reset(base)
    label = "agent ON" if state else "agent OFF"
    print(c(f"\nTarget {base} · {label}", BOLD + ";" + (GREEN if state else RED)))
    if args.attack == "all":
        results = run_all(base)
        print_summary(results, label)
    else:
        print_summary([ATTACKS[args.attack](base)], label)
    print(c(f"\n   Dashboard: {base}/admin", DIM))


if __name__ == "__main__":
    t0 = time.time()
    main()
