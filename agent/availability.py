"""Availability shield: keeps the portal up on results day.

Two kinds of heavy traffic, two answers:

  * BAD traffic (a flood): a few sources sending far more requests than any person
    could. Every single request looks normal, so the other rules never fire. Kavach
    counts requests per source per second and refuses a source that goes over the
    limit for a short while (HTTP 429), with no database work.

  * GOOD traffic (a rush): thousands of real, logged-in students opening their results
    at once. Nobody is blocked. When the portal starts to slow down, Kavach switches
    on RUSH MODE:
      - lanes: fee payment, receipts and login keep a reserved lane and never wait
        behind results;
      - results are served through a fair queue (one place per student, however often
        they refresh) and from a short cache, since published results do not change;
      - library and admissions search are paused for a few minutes.
    It switches rush mode off by itself when traffic is back to normal.

  * WATCHING: a watchdog checks the portal every second (response time, requests per
    second, errors, requests waiting) and alerts the IT head when it turns SLOW or DOWN.

This module runs AFTER the main gateway (agent/gateway.py), so anything the gateway
already blocks never reaches it, and it only acts while the agent is ON. Its numbers
sit far above what one person or the attack simulator's other attacks produce.
"""
from __future__ import annotations

import asyncio
import math
import re
import time
from collections import OrderedDict, deque
from contextlib import closing

from fastapi import Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response

from app import auth, db
from . import actions, config, detector, inspector, ledger, notify

DEVICE_RX = re.compile(r"^[A-Za-z0-9_-]{20,40}$")
LANES = ("critical", "results", "deferrable", "standard")


def enabled() -> bool:
    return config.AVAILABILITY_SHIELD and ledger.enabled()


def shedding() -> bool:
    """True while rush mode is on: Kavach pauses its own optional per-request work."""
    return S.rush and enabled()


def lane_of(path: str) -> str:
    for lane, prefixes in config.LANES.items():
        if path.startswith(prefixes):
            return lane
    return "standard"


class _State:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.inflight = {lane: 0 for lane in LANES}
        self.done: deque = deque(maxlen=5000)          # (ts, ms, lane, status) of finished requests
        self.points: deque = deque(maxlen=config.HEALTH_HISTORY)
        self.status = "UP"
        self.rush = False
        self.rush_since = 0.0
        self.calm_since = 0.0
        self.rush_inc: dict | None = None
        self.rush_peak = {"queue": 0, "inflight": 0, "wait": 0}
        self.waiting: OrderedDict = OrderedDict()      # student -> time they joined the results line
        self.results_sem: asyncio.Semaphore | None = None  # results slots during rush mode (FIFO)
        self.cache: dict = {}                           # roll -> (ts, status, body, headers)
        self.hits: dict = {}                            # bucket -> deque of request times
        self.open: dict = {}                            # bucket -> requests from it in progress right now
        self.all_hits: deque = deque()                  # every counted request (for each source's share)
        self.flood_until: dict = {}                     # bucket -> refused until
        self.flood_inc: dict | None = None
        self.flood_sources: set = set()
        self.unflushed_blocked = 0
        self.c = {"flood_refused": 0, "queued": 0, "deferred": 0, "cache_hits": 0, "served_results": 0,
                  "critical_served": 0, "critical_ms": 0.0, "critical_max": 0.0}


S = _State()


def reset() -> None:
    S.reset()


# ====================================================================== middleware
async def middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith(config.EXEMPT_PREFIXES):
        return await call_next(request)
    lane = lane_of(path)
    on = enabled()
    held = None                                         # results slot taken during rush mode

    bucket = None
    if on:
        refused, bucket = _flood_check(request, path)
        if refused is not None:
            return refused
        request.state.flood_bucket = bucket
        if S.rush:
            if lane == "deferrable":
                S.c["deferred"] += 1
                return JSONResponse({"error": "Paused for a few minutes during the results-day rush so that results "
                                              "and fee payments stay fast. Please try again shortly.",
                                     "deferred": True, "by": "Kavach"}, status_code=503, headers={"Retry-After": "60"})
            if lane == "results":
                roll = _own_roll(request)
                if roll:
                    hit = _cache_get(roll, request)
                    if hit is not None:
                        return hit
                    waiting = await _results_slot(roll)
                    if waiting is not None:
                        return waiting
                    held = S.results_sem

    t0 = time.perf_counter()
    S.inflight[lane] += 1
    if bucket:
        S.open[bucket] = S.open.get(bucket, 0) + 1
    try:
        resp = await call_next(request)
    finally:
        S.inflight[lane] -= 1
        if bucket:
            S.open[bucket] -= 1
            if S.open[bucket] <= 0:
                S.open.pop(bucket, None)
        if held is not None:
            held.release()
    ms = (time.perf_counter() - t0) * 1000
    S.done.append((time.time(), ms, lane, resp.status_code))
    if lane == "critical":
        S.c["critical_served"] += 1
        S.c["critical_ms"] += ms
        S.c["critical_max"] = max(S.c["critical_max"], ms)
    if on and lane == "results" and resp.status_code == 200:
        S.c["served_results"] += 1
        if S.rush:
            roll = _own_roll(request)
            if roll:
                return await _cache_put(roll, resp)
    return resp


# ---------------------------------------------------------------- flood gate (in front of the gateway)
async def flood_gate(request: Request, call_next):
    """Refuses sources ALREADY marked as flooding, before the gateway inspects anything: a refusal
    must cost almost nothing, or the flood just moves from the portal to Kavach itself. It never
    acts on anyone the flood shield below has not marked."""
    if S.flood_until and enabled() and not request.url.path.startswith(config.EXEMPT_PREFIXES):
        ip = inspector.client_ip(request)
        device = request.cookies.get(auth.DEVICE_COOKIE, "") or ""
        bucket = f"dev|{ip}|{device}" if DEVICE_RX.match(device) else f"nocookie|{ip}"
        until = S.flood_until.get(bucket)
        if until and until > time.time():
            S.c["flood_refused"] += 1
            S.unflushed_blocked += 1
            s = max(1, math.ceil(until - time.time()))
            return JSONResponse({"blocked": True, "by": "Kavach", "code": "flood", "retry_after": s,
                                 "reason": f"Too many requests from your connection: Kavach is protecting the portal "
                                           f"from a traffic flood. Try again in {s} seconds."},
                                status_code=429, headers={"Retry-After": str(s)})
    return await call_next(request)


# ---------------------------------------------------------------- flood shield
def _flood_check(request: Request, path: str):
    ip = getattr(request.state, "ip", None) or (request.client.host if request.client else "?")
    device = getattr(request.state, "device", "")
    # Browsers keep their device cookie; bots that drop cookies get a new device on every
    # request, so those are counted together per IP instead.
    has_cookie = bool(DEVICE_RX.match(request.cookies.get(auth.DEVICE_COOKIE, "") or ""))
    bucket = f"dev|{ip}|{device}" if has_cookie else f"nocookie|{ip}"
    now = time.time()
    until = S.flood_until.get(bucket)
    if until and until > now:
        S.c["flood_refused"] += 1
        S.unflushed_blocked += 1
        return _too_many(request, until - now), bucket
    dq = S.hits.get(bucket)
    if dq is None:
        dq = S.hits[bucket] = deque()
    dq.append(now)
    while dq and now - dq[0] > 10:
        dq.popleft()
    S.all_hits.append(now)
    while S.all_hits and now - S.all_hits[0] > 5:
        S.all_hits.popleft()
    n1 = n5 = 0
    for t in reversed(dq):
        if now - t > 5:
            break
        n5 += 1
        if now - t <= 1:
            n1 += 1
    per_1, per_10 = ((config.FLOOD_PER_SECOND, config.FLOOD_PER_10_SECONDS) if has_cookie else
                     (config.FLOOD_COOKIELESS_PER_SECOND, config.FLOOD_COOKIELESS_PER_10_SECONDS))
    # Fair share: when the portal is busy, a slow server caps how fast any bot CAN send, so a
    # fixed speed limit is never reached. One source taking a big slice of all traffic is a flood.
    share = n5 / len(S.all_hits) if S.all_hits else 0.0
    busy = sum(S.inflight.values()) >= config.FLOOD_BUSY_INFLIGHT or S.status != "UP"
    greedy = busy and n5 / 5 >= config.FLOOD_SHARE_MIN_RPS and share >= config.FLOOD_SHARE
    # Too many open at once: a person's page has at most about 4 requests in progress, a bot
    # holds many connections open. Works even when a slow server caps how fast anyone can send.
    open_now = S.open.get(bucket, 0) + 1
    hoarding = open_now > (config.FLOOD_MAX_OPEN if has_cookie else config.FLOOD_COOKIELESS_MAX_OPEN)
    if n1 <= per_1 and len(dq) <= per_10 and not greedy and not hoarding:
        return None, bucket

    S.flood_until[bucket] = now + config.FLOOD_BLOCK_SECONDS
    S.c["flood_refused"] += 1
    S.unflushed_blocked += 1
    first = ip not in S.flood_sources
    S.flood_sources.add(ip)
    who = f"IP {ip}" + ("" if not has_cookie else f" (device {device[:6]}…)")
    inc = S.flood_inc if S.flood_inc and S.flood_inc["id"] in ledger.INCIDENTS else None
    if inc is None or now - inc["last_seen"] > config.WINDOW_SECONDS:
        inc = ledger.incident("flood", "flood", "Traffic flood blocked", path,
                              {"ip": ip, "device": device[:6] + "…", "roll": None, "name": None})
        S.flood_inc = inc
        notify.it_head("flood", "Traffic flood blocked", f"A source sent {n1} requests in one second. Kavach refuses "
                       f"flooding sources for {config.FLOOD_BLOCK_SECONDS} s; real students are unaffected.")
    risk, sev = detector.score(["flood"])
    n_src = len(S.flood_sources)
    ledger.update_incident(inc, risk=risk, severity=sev, title=f"Traffic flood blocked: {n_src} source(s)",
                           action=f"Each flooding source refused for {config.FLOOD_BLOCK_SECONDS} s (HTTP 429) "
                                  f"before any database work; real students keep being served",
                           reasons=[(f"{who} had {open_now} requests open at once; a person's page has at most about 4"
                                     if hoarding and n1 <= per_1 and not greedy else
                                     f"{who} took {round(share * 100)}% of all traffic ({n5} requests in 5 s) while the "
                                     f"portal was busy; a person clicking sends about 1/s" if greedy and n1 <= per_1 else
                                     f"{who} sent {n1} requests in 1 s ({len(dq)} in 10 s); the limit is "
                                     f"{per_1}/s, a person clicking sends about 1/s")] if first and n_src <= 5 else None,
                           evidence=[{"source": ip, "per_second": n1, "cookie": has_cookie}] if first else None)
    ledger.event("block", f"Traffic flood: a source was sending far more than a person could and is refused "
                          f"for {config.FLOOD_BLOCK_SECONDS} s", inc["id"])
    return _too_many(request, config.FLOOD_BLOCK_SECONDS), bucket


def flooding(request: Request) -> bool:
    """Is this request's source marked as flooding? Lets requests already waiting in line be dropped."""
    bucket = getattr(request.state, "flood_bucket", None)
    until = S.flood_until.get(bucket) if bucket else None
    return bool(until and until > time.time() and enabled())


def _too_many(request: Request, seconds: float):
    s = max(1, math.ceil(seconds))
    resp = actions.blocked_response(request, f"Too many requests from your connection: Kavach is protecting the "
                                    f"portal from a traffic flood. Try again in {s} seconds.",
                                    S.flood_inc["id"] if S.flood_inc else None, code="flood", status=429,
                                    extra={"retry_after": s})
    resp.headers["Retry-After"] = str(s)
    return resp


# ---------------------------------------------------------------- results lane: queue + cache
def _own_roll(request: Request) -> str | None:
    s = auth.get_session(request.cookies.get(auth.SESSION_COOKIE))
    if not s:
        return None
    asked = request.query_params.get("roll")
    return s.roll if not asked or asked == s.roll else None


async def _results_slot(key: str):
    """Wait, without using the CPU, for one of the results slots, in arrival order.
    None = slot taken (the caller releases it). Otherwise a 'you're number N in line' reply:
    for a second request from a student already in line, or after QUEUE_HOLD_SECONDS."""
    if S.results_sem is None:
        S.results_sem = asyncio.Semaphore(config.RESULTS_SLOTS)
    if key in S.waiting:
        return _queued_reply(key, retry_ms=1000)
    S.waiting[key] = time.time()
    S.rush_peak["queue"] = max(S.rush_peak["queue"], len(S.waiting))
    try:
        await asyncio.wait_for(S.results_sem.acquire(), timeout=config.QUEUE_HOLD_SECONDS)
    except asyncio.TimeoutError:
        reply = _queued_reply(key, retry_ms=300)
        S.waiting.pop(key, None)
        return reply
    joined = S.waiting.pop(key, time.time())
    S.rush_peak["wait"] = max(S.rush_peak["wait"], int(time.time() - joined))
    return None


def _queued_reply(key: str, retry_ms: int):
    pos = (list(S.waiting).index(key) + 1) if key in S.waiting else len(S.waiting) + 1
    rate = _rate("results", 5) or 1.0
    wait = max(1, math.ceil(pos / rate))
    S.c["queued"] += 1
    return JSONResponse({"queued": True, "position": pos, "wait_seconds": wait, "retry_ms": retry_ms, "by": "Kavach",
                         "message": f"Results day is busy. You're number {pos} in line (about {wait} s). This page "
                                    f"opens by itself; fee payment is not affected."},
                        status_code=503, headers={"Retry-After": "1"})


def _cache_get(roll: str, request: Request):
    hit = S.cache.get(roll)
    if not hit or time.time() - hit[0] > config.RESULTS_CACHE_SECONDS:
        return None
    S.c["cache_hits"] += 1
    S.c["served_results"] += 1
    _, status, body, headers = hit
    resp = Response(content=body, status_code=status, media_type="application/json")
    resp.headers["X-Kavach-Cache"] = "hit"
    return resp


async def _cache_put(roll: str, resp):
    body = b"".join([chunk async for chunk in resp.body_iterator])
    S.cache[roll] = (time.time(), resp.status_code, body, None)
    new = Response(content=body, status_code=resp.status_code, media_type=resp.media_type or "application/json")
    for k, v in resp.raw_headers:
        if k not in (b"content-length", b"content-type"):
            new.raw_headers.append((k, v))
    return new


# ====================================================================== watchdog
def _window(seconds: float) -> list:
    now = time.time()
    out = []
    for item in reversed(S.done):
        if now - item[0] > seconds:
            break
        out.append(item)
    return out


def _rate(lane: str, seconds: float) -> float:
    return sum(1 for d in _window(seconds) if d[2] == lane) / seconds


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return v[min(len(v) - 1, int(len(v) * 0.95))]


def _probe() -> None:
    with closing(db.connect()) as conn:
        conn.execute("SELECT 1 FROM students LIMIT 1").fetchone()


async def watchdog() -> None:
    """Runs for the life of the server: one health point per interval."""
    while True:
        await asyncio.sleep(config.HEALTH_INTERVAL)
        try:
            await _tick()
        except Exception as e:                          # the watchdog must never die
            ledger.event("warn", f"Health watchdog error: {e}")


async def _tick() -> None:
    t0 = time.perf_counter()
    failed = False
    try:
        await asyncio.wait_for(run_in_threadpool(_probe), timeout=config.HEALTH_DOWN_MS / 1000)
    except Exception:
        failed = True
    probe_ms = (time.perf_counter() - t0) * 1000
    win = _window(5)
    pages = [d for d in win if d[3] not in (429, 503)]
    p95 = _p95([d[1] for d in pages])
    rps = len(win) / 5
    errors = sum(1 for d in win if d[3] >= 500 and d[3] != 503)
    inflight = sum(S.inflight.values())
    worst = max(probe_ms, p95)
    status = "DOWN" if failed or worst >= config.HEALTH_DOWN_MS else "SLOW" if worst >= config.HEALTH_SLOW_MS else "UP"
    on = enabled()
    S.points.append({"ts": time.time(), "ms": round(worst), "probe_ms": round(probe_ms), "p95": round(p95),
                     "rps": round(rps, 1), "errors": errors, "inflight": inflight, "queue": len(S.waiting),
                     "status": status, "rush": S.rush, "agent": on})

    if status != S.status:
        if on:
            level = "critical" if status == "DOWN" else "warn" if status == "SLOW" else "info"
            ledger.event(level, f"Portal health: {S.status} → {status} (response {round(worst)} ms, "
                                f"{round(rps)} requests/s, {inflight} waiting)", dedupe=False)
            if status != "UP":
                notify.it_head("health", f"Portal is {status}", f"Response time {round(worst)} ms with {round(rps)} "
                               f"requests/s and {inflight} waiting. Kavach is managing the load.")
        S.status = status

    if on:
        _rush_decide(inflight, p95, rps, len(win))
        if S.unflushed_blocked:
            ledger.bump("blocked", S.unflushed_blocked)
            S.unflushed_blocked = 0
    elif S.rush:
        _rush_off("the agent was switched OFF")


def _rush_decide(inflight: int, p95: float, rps: float, n: int) -> None:
    now = time.time()
    busy = inflight >= config.RUSH_ENTER_INFLIGHT or (n >= 20 and p95 >= config.RUSH_ENTER_MS)
    if not S.rush:
        if busy:
            S.rush, S.rush_since, S.calm_since = True, now, 0.0
            S.rush_peak = {"queue": 0, "inflight": inflight, "wait": 0}
            for k in ("queued", "deferred", "cache_hits", "served_results", "critical_served"):
                S.c[k] = 0
            S.c["critical_ms"] = S.c["critical_max"] = 0.0
            inc = ledger.incident("rush", "portal", "Results-day rush: rush mode switched ON", "/api/results",
                                  {"ip": "many students", "device": "-", "roll": None, "name": None})
            S.rush_inc = inc
            risk, sev = detector.score(["rush"])
            ledger.update_incident(inc, risk=risk, severity=sev,
                                   action="Rush mode: fee payment, receipts and login kept on a reserved lane; results "
                                          "served through a fair queue and a short cache; library and admissions "
                                          "search paused",
                                   reasons=[f"{inflight} requests waiting at once and {round(rps)} requests/s "
                                            f"(p95 response {round(p95)} ms); normal is under "
                                            f"{config.RUSH_ENTER_INFLIGHT} waiting",
                                            "Every request came from real logged-in students, so nobody is blocked"])
            ledger.event("warn", f"Rush mode ON: {inflight} requests waiting, {round(rps)} requests/s. Fees keep a "
                                 f"reserved lane, results go through a fair queue", inc["id"], dedupe=False)
            notify.it_head("rush", "Results-day rush: rush mode ON",
                           "Fee payment and login are on a reserved lane; results are queued fairly; library and "
                           "admissions search are paused until traffic is back to normal.")
        return
    S.rush_peak["inflight"] = max(S.rush_peak["inflight"], inflight)
    calm = inflight <= config.RUSH_EXIT_INFLIGHT and not S.waiting and p95 < config.RUSH_ENTER_MS / 2
    if not calm:
        S.calm_since = 0.0
    elif not S.calm_since:
        S.calm_since = now
    elif now - S.calm_since >= config.RUSH_CALM_SECONDS:
        _rush_off("traffic is back to normal")


def _rush_off(why: str) -> None:
    secs = int(time.time() - S.rush_since)
    crit = S.c["critical_served"]
    avg = round(S.c["critical_ms"] / crit) if crit else 0
    inc = S.rush_inc
    if inc and inc["id"] in ledger.INCIDENTS:
        ledger.update_incident(inc, title=f"Results-day rush handled ({secs} s, nobody blocked)", reasons=[
            f"Peak: {S.rush_peak['inflight']} requests waiting at once; up to {S.rush_peak['queue']} students in the "
            f"results queue, longest wait about {S.rush_peak['wait']} s",
            f"Fee payment / receipts / login: {crit} requests served on the reserved lane, average {avg} ms, "
            f"slowest {round(S.c['critical_max'])} ms, none queued",
            f"Results: {S.c['served_results']} served ({S.c['cache_hits']} from the short cache); "
            f"{S.c['queued']} 'please wait' replies instead of a crash",
            f"Library / admissions requests paused: {S.c['deferred']}",
        ])
    ledger.event("info", f"Rush mode OFF after {secs} s: {why}. Fees served {crit} times, average {avg} ms",
                 inc["id"] if inc else None, dedupe=False)
    notify.it_head("rush", "Rush mode OFF", f"After {secs} s: {why}. Fee requests stayed on the reserved lane "
                   f"(average {avg} ms).")
    S.rush = False
    S.cache.clear()
    S.calm_since = 0.0


# ====================================================================== dashboard data
def snapshot() -> dict:
    crit = S.c["critical_served"]
    return {
        "enabled": enabled(), "status": S.status, "rush": S.rush,
        "rush_for": int(time.time() - S.rush_since) if S.rush else 0,
        "inflight": dict(S.inflight), "queue": len(S.waiting),
        "points": list(S.points),
        "counters": {**S.c, "critical_avg_ms": round(S.c["critical_ms"] / crit) if crit else 0,
                     "flood_sources": len(S.flood_sources)},
        "thresholds": {"slow_ms": config.HEALTH_SLOW_MS, "down_ms": config.HEALTH_DOWN_MS,
                       "flood_per_second": config.FLOOD_PER_SECOND, "results_slots": config.RESULTS_SLOTS,
                       "rush_enter_inflight": config.RUSH_ENTER_INFLIGHT, "interval": config.HEALTH_INTERVAL},
    }
