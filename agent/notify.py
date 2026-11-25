"""In-app notifications for students (portal bell / Account page) and the IT head (dashboard)."""
from __future__ import annotations

import json
import time

from . import ledger


def _insert(audience: str, roll: str | None, kind: str, title: str, body: str, action: dict | None) -> int:
    cur = ledger._x("INSERT INTO notifications (ts, audience, roll, kind, title, body, action) VALUES (?,?,?,?,?,?,?)",
                    (time.time(), audience, roll, kind, title, body, json.dumps(action) if action else None))
    return cur.lastrowid


def student(roll: str, kind: str, title: str, body: str, action: dict | None = None) -> int:
    nid = _insert("student", roll, kind, title, body, action)
    ledger.event("info", f"Notified student {roll}: {title}")
    return nid


def it_head(kind: str, title: str, body: str) -> int:
    return _insert("it", None, kind, title, body, None)


def for_student(roll: str, limit: int = 30) -> list[dict]:
    rows = ledger._x("SELECT * FROM notifications WHERE audience='student' AND roll = ? ORDER BY id DESC LIMIT ?",
                     (roll, limit)).fetchall()
    return [_row(r) for r in rows]


def recent(limit: int = 25) -> list[dict]:
    rows = ledger._x("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_row(r) for r in rows]


def unread(roll: str) -> int:
    return ledger._x("SELECT COUNT(*) FROM notifications WHERE audience='student' AND roll = ? AND read = 0",
                     (roll,)).fetchone()[0]


def mark_read(roll: str) -> None:
    ledger._x("UPDATE notifications SET read = 1 WHERE audience='student' AND roll = ?", (roll,))


def get(nid: int) -> dict | None:
    r = ledger._x("SELECT * FROM notifications WHERE id = ?", (nid,)).fetchone()
    return _row(r) if r else None


def _row(r) -> dict:
    d = dict(r)
    d["action"] = json.loads(d["action"]) if d["action"] else None
    return d
