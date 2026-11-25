"""Leak ledger: incidents, leaked/protected records, live events, stats, blocks.

Write-through: every change goes to SQLite (survives a restart) and to an
in-memory cache (the dashboard polls every second, so reads stay cheap).
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from collections import deque

from . import config

_lock = threading.RLock()

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS stats (key TEXT PRIMARY KEY, value INTEGER);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, ts REAL, level TEXT, message TEXT, incident_id TEXT, count INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, type TEXT, actor_key TEXT, title TEXT, severity TEXT, risk INTEGER,
    first_seen REAL, last_seen REAL, reasons TEXT, action TEXT, records_leaked INTEGER,
    records_protected INTEGER, evidence TEXT, endpoint TEXT, actor TEXT, version INTEGER, requests INTEGER
);
CREATE TABLE IF NOT EXISTS leaks (
    id INTEGER PRIMARY KEY, ts REAL, record_id TEXT, owner_name TEXT, fields TEXT, to_whom TEXT,
    ip TEXT, endpoint TEXT, incident_id TEXT, outcome TEXT
);
CREATE TABLE IF NOT EXISTS blocks (
    key TEXT PRIMARY KEY, ip TEXT, device TEXT, reason TEXT, until REAL, incident_id TEXT
);
CREATE TABLE IF NOT EXISTS frozen (
    roll TEXT PRIMARY KEY, reason TEXT, until REAL, incident_id TEXT, otp TEXT
);
CREATE TABLE IF NOT EXISTS known_devices (
    roll TEXT, device TEXT, first_seen REAL, trusted INTEGER, PRIMARY KEY (roll, device)
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY, ts REAL, audience TEXT, roll TEXT, kind TEXT, title TEXT,
    body TEXT, action TEXT, read INTEGER DEFAULT 0
);
"""

STAT_KEYS = ("inspected", "blocked", "leaked", "protected")

_conn: sqlite3.Connection | None = None
STATE: dict = {"enabled": True}
STATS: dict[str, int] = {k: 0 for k in STAT_KEYS}
INCIDENTS: dict[str, dict] = {}
EVENTS: deque = deque(maxlen=400)
LEAKS: deque = deque(maxlen=400)
BLOCKS: dict[str, dict] = {}
FROZEN: dict[str, dict] = {}
_leak_seen: set[tuple] = set()


def conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        config.DATA_DIR.mkdir(exist_ok=True)
        _conn = sqlite3.connect(config.LEDGER_DB, check_same_thread=False, timeout=10, isolation_level=None)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        _conn.execute("PRAGMA synchronous=NORMAL")
    return _conn


def _x(sql: str, args: tuple = ()) -> sqlite3.Cursor:
    with _lock:
        return conn().execute(sql, args)


# ---------------------------------------------------------------- load / reset
def load() -> None:
    """Warm the in-memory cache from SQLite at startup."""
    with _lock:
        c = conn()
        row = c.execute("SELECT value FROM settings WHERE key='enabled'").fetchone()
        STATE["enabled"] = (row["value"] == "1") if row else True
        for r in c.execute("SELECT key, value FROM stats"):
            STATS[r["key"]] = r["value"]
        INCIDENTS.clear()
        for r in c.execute("SELECT * FROM incidents"):
            INCIDENTS[r["id"]] = _inc_from_row(r)
        EVENTS.clear()
        for r in reversed(c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 400").fetchall()):
            EVENTS.append(dict(r))
        LEAKS.clear()
        _leak_seen.clear()
        for r in reversed(c.execute("SELECT * FROM leaks ORDER BY id DESC LIMIT 400").fetchall()):
            d = dict(r)
            d["fields"] = json.loads(d["fields"])
            LEAKS.append(d)
            _leak_seen.add((d["record_id"], d["endpoint"], d["to_whom"], d["incident_id"]))
        now = time.time()
        BLOCKS.clear()
        for r in c.execute("SELECT * FROM blocks WHERE until > ?", (now,)):
            BLOCKS[r["key"]] = dict(r)
        FROZEN.clear()
        for r in c.execute("SELECT * FROM frozen WHERE until > ?", (now,)):
            FROZEN[r["roll"]] = dict(r)


def reset() -> None:
    with _lock:
        c = conn()
        for t in ("stats", "events", "incidents", "leaks", "blocks", "frozen", "known_devices", "notifications"):
            c.execute(f"DELETE FROM {t}")
        STATS.update({k: 0 for k in STAT_KEYS})
        for d in (INCIDENTS, BLOCKS, FROZEN):
            d.clear()
        EVENTS.clear()
        LEAKS.clear()
        _leak_seen.clear()


def _inc_from_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["reasons"] = json.loads(d["reasons"] or "[]")
    d["evidence"] = json.loads(d["evidence"] or "[]")
    d["actor"] = json.loads(d["actor"] or "{}")
    return d


# ---------------------------------------------------------------- settings / stats
def enabled() -> bool:
    return STATE["enabled"]


def set_enabled(on: bool) -> None:
    STATE["enabled"] = bool(on)
    _x("INSERT OR REPLACE INTO settings VALUES ('enabled', ?)", ("1" if on else "0",))


def bump(key: str, n: int = 1) -> None:
    if n <= 0:
        return
    with _lock:
        STATS[key] = STATS.get(key, 0) + n
        conn().execute("INSERT OR REPLACE INTO stats VALUES (?, ?)", (key, STATS[key]))


# ---------------------------------------------------------------- events
def event(level: str, message: str, incident_id: str | None = None, dedupe: bool = True) -> None:
    """level: info | warn | block | leak | protect | critical. Repeats within 6s collapse into one line (×N)."""
    now = time.time()
    with _lock:
        last = EVENTS[-1] if EVENTS else None
        if dedupe and last and last["message"] == message and last["level"] == level and now - last["ts"] < 6:
            last["count"] += 1
            last["ts"] = now
            conn().execute("UPDATE events SET count = ?, ts = ? WHERE id = ?", (last["count"], now, last["id"]))
            return
        cur = conn().execute("INSERT INTO events (ts, level, message, incident_id, count) VALUES (?,?,?,?,1)",
                             (now, level, message, incident_id))
        EVENTS.append({"id": cur.lastrowid, "ts": now, "level": level, "message": message,
                       "incident_id": incident_id, "count": 1})


# ---------------------------------------------------------------- incidents
def _next_incident_id() -> str:
    n = 1 + max((int(i.split("-")[1]) for i in INCIDENTS), default=0)
    return f"INC-{n:04d}"


def incident(type_: str, actor_key: str, title: str, endpoint: str, actor: dict) -> dict:
    """Return the open incident for (type, actor) or create one."""
    now = time.time()
    with _lock:
        for inc in INCIDENTS.values():
            if inc["type"] == type_ and inc["actor_key"] == actor_key and now - inc["last_seen"] < config.WINDOW_SECONDS * 2:
                return inc
        inc = {"id": _next_incident_id(), "type": type_, "actor_key": actor_key, "title": title,
               "severity": "low", "risk": 0, "first_seen": now, "last_seen": now, "reasons": [],
               "action": "Flagged", "records_leaked": 0, "records_protected": 0, "evidence": [],
               "endpoint": endpoint, "actor": actor, "version": 1, "requests": 0}
        INCIDENTS[inc["id"]] = inc
        _save_incident(inc)
        return inc


def update_incident(inc: dict, *, risk: int | None = None, severity: str | None = None,
                    reasons: list[str] | None = None, action: str | None = None, leaked: int = 0,
                    protected: int = 0, evidence: list[dict] | None = None, title: str | None = None,
                    actor: dict | None = None) -> dict:
    with _lock:
        inc["last_seen"] = time.time()
        inc["requests"] = inc.get("requests", 0) + 1
        changed = False
        if risk is not None and risk > inc["risk"]:
            inc["risk"] = risk
            changed = True
        if severity and _sev_rank(severity) > _sev_rank(inc["severity"]):
            inc["severity"] = severity
            changed = True
        for r in reasons or []:
            if r not in inc["reasons"]:
                inc["reasons"].append(r)
                changed = True
        if action and action != inc["action"]:
            inc["action"] = action
            changed = True
        if title and title != inc["title"]:
            inc["title"] = title
            changed = True
        if actor:
            inc["actor"].update({k: v for k, v in actor.items() if v})
        if leaked or protected:
            inc["records_leaked"] += leaked
            inc["records_protected"] += protected
            changed = True
        for e in evidence or []:
            if len(inc["evidence"]) < 8:
                inc["evidence"].append(e)
                changed = True
        if changed:
            inc["version"] += 1
        _save_incident(inc)
        return inc


def _sev_rank(s: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(s, 0)


def _save_incident(inc: dict) -> None:
    _x("INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
       (inc["id"], inc["type"], inc["actor_key"], inc["title"], inc["severity"], inc["risk"],
        inc["first_seen"], inc["last_seen"], json.dumps(inc["reasons"]), inc["action"],
        inc["records_leaked"], inc["records_protected"], json.dumps(inc["evidence"]),
        inc["endpoint"], json.dumps(inc["actor"]), inc["version"], inc.get("requests", 0)))


# ---------------------------------------------------------------- leak rows
def add_leaks(rows: list[dict]) -> int:
    """rows: record_id, owner_name, fields, to_whom, ip, endpoint, incident_id, outcome. Deduplicated per incident."""
    now = time.time()
    fresh = []
    with _lock:
        for r in rows:
            k = (r["record_id"], r["endpoint"], r["to_whom"], r["incident_id"])
            if k in _leak_seen:
                continue
            _leak_seen.add(k)
            fresh.append(r)
        if not fresh:
            return 0
        c = conn()
        for r in fresh:
            cur = c.execute("INSERT INTO leaks (ts, record_id, owner_name, fields, to_whom, ip, endpoint, incident_id, outcome) "
                            "VALUES (?,?,?,?,?,?,?,?,?)",
                            (now, r["record_id"], r.get("owner_name"), json.dumps(r["fields"]), r["to_whom"],
                             r["ip"], r["endpoint"], r["incident_id"], r["outcome"]))
            LEAKS.append({**r, "id": cur.lastrowid, "ts": now})
    return len(fresh)


def leaks_for(incident_id: str) -> list[dict]:
    rows = _x("SELECT * FROM leaks WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["fields"] = json.loads(d["fields"])
        out.append(d)
    return out


# ---------------------------------------------------------------- blocks / freezes
def block(ip: str, device: str | None, reason: str, incident_id: str | None, seconds: int = config.BLOCK_SECONDS) -> dict:
    key = f"{ip}|{device or '*'}"
    b = {"key": key, "ip": ip, "device": device or "*", "reason": reason,
         "until": time.time() + seconds, "incident_id": incident_id}
    with _lock:
        BLOCKS[key] = b
        conn().execute("INSERT OR REPLACE INTO blocks VALUES (?,?,?,?,?,?)",
                       (key, ip, b["device"], reason, b["until"], incident_id))
    return b


def blocked(ip: str, device: str) -> dict | None:
    now = time.time()
    for key in (f"{ip}|{device}", f"{ip}|*"):
        b = BLOCKS.get(key)
        if b and b["until"] > now:
            return b
    return None


def ip_has_blocked_device(ip: str, except_device: str) -> bool:
    now = time.time()
    return any(b["ip"] == ip and b["device"] != except_device and b["until"] > now for b in BLOCKS.values())


def freeze(roll: str, reason: str, incident_id: str | None) -> dict:
    otp = f"{secrets.randbelow(900000) + 100000}"
    f = {"roll": roll, "reason": reason, "until": time.time() + config.FREEZE_SECONDS,
         "incident_id": incident_id, "otp": otp}
    with _lock:
        FROZEN[roll] = f
        conn().execute("INSERT OR REPLACE INTO frozen VALUES (?,?,?,?,?)", (roll, reason, f["until"], incident_id, otp))
    return f


def frozen(roll: str | None) -> dict | None:
    if not roll:
        return None
    f = FROZEN.get(roll)
    return f if f and f["until"] > time.time() else None


def unfreeze(roll: str) -> None:
    with _lock:
        FROZEN.pop(roll, None)
        conn().execute("DELETE FROM frozen WHERE roll = ?", (roll,))


# ---------------------------------------------------------------- known devices
def device_status(roll: str, device: str) -> str:
    """'new' | 'untrusted' | 'trusted'"""
    r = _x("SELECT trusted FROM known_devices WHERE roll = ? AND device = ?", (roll, device)).fetchone()
    if not r:
        return "new"
    return "trusted" if r["trusted"] else "untrusted"


def remember_device(roll: str, device: str, trusted: bool = False) -> None:
    _x("INSERT OR IGNORE INTO known_devices VALUES (?,?,?,?)", (roll, device, time.time(), 1 if trusted else 0))
    if trusted:
        _x("UPDATE known_devices SET trusted = 1 WHERE roll = ? AND device = ?", (roll, device))


def devices_for(roll: str) -> list[dict]:
    return [dict(r) for r in _x("SELECT * FROM known_devices WHERE roll = ? ORDER BY first_seen", (roll,)).fetchall()]


# ---------------------------------------------------------------- snapshot for the dashboard
def snapshot() -> dict:
    with _lock:
        events = list(EVENTS)[-80:]
        incs = sorted(INCIDENTS.values(), key=lambda i: i["last_seen"], reverse=True)
        return {
            "enabled": STATE["enabled"],
            "stats": dict(STATS),
            "events": [dict(e) for e in events],
            "incidents": [{k: v for k, v in i.items()} for i in incs[:60]],
            "leaks": list(reversed(list(LEAKS)))[:150],
            "blocks": [b for b in BLOCKS.values() if b["until"] > time.time()],
            "frozen": [{k: v for k, v in f.items() if k != "otp"} for f in FROZEN.values() if f["until"] > time.time()],
        }
