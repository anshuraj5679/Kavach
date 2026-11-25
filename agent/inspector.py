"""Request inspector: runs BEFORE the request reaches the portal or the database."""
from __future__ import annotations

import json
import re
import time
from urllib.parse import parse_qsl

from fastapi import Request

from . import config


def client_ip(request: Request) -> str:
    """Client IP for attribution.

    Reads X-Forwarded-For so the localhost attack simulator can play several
    attackers from one machine. IN PRODUCTION: trust X-Forwarded-For only when
    the direct peer is your own reverse proxy, otherwise anyone can forge it
    and dodge per-IP blocks. Use request.client.host for untrusted peers.
    """
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


# ---------------------------------------------------------------- SQL injection
# Each pattern needs SQL *structure*, so a name like "D'Souza" or "O'Brien" passes.
SQLI_PATTERNS = [
    (re.compile(r"'\s*(or|and)\s+'?[\w-]*'?\s*(=|like|<|>)", re.I), "quote followed by OR/AND comparison (tautology)"),
    (re.compile(r"\b(or|and)\s+\d+\s*=\s*\d+", re.I), "numeric tautology (OR 1=1)"),
    (re.compile(r"'\s*=\s*'", re.I), "string tautology ('1'='1')"),
    (re.compile(r"\bunion\b[\s/*]+(all\s+)?select\b", re.I), "UNION SELECT"),
    (re.compile(r";\s*(drop|delete|insert|update|alter|create|attach|pragma)\b", re.I), "stacked query"),
    (re.compile(r"(--|#)\s*$|/\*", re.I), "SQL comment used to cut off the query"),
    (re.compile(r"\b(sleep|benchmark|randomblob|load_extension)\s*\(", re.I), "time / function based probe"),
    (re.compile(r"\bselect\b.+\bfrom\b", re.I), "embedded SELECT ... FROM"),
    (re.compile(r"\bsqlite_master\b|\binformation_schema\b", re.I), "schema discovery"),
]


def request_values(request: Request, body: bytes) -> list[tuple[str, str]]:
    """Every user-controlled string: query params, JSON body leaves, form fields."""
    vals = [(k, v) for k, v in request.query_params.multi_items()]
    if body:
        ctype = request.headers.get("content-type", "")
        if "json" in ctype:
            try:
                _flatten("", json.loads(body), vals)
            except (ValueError, UnicodeDecodeError):
                vals.append(("body", body.decode("utf-8", "replace")))
        elif "form" in ctype:
            vals.extend(parse_qsl(body.decode("utf-8", "replace")))
        else:
            vals.append(("body", body.decode("utf-8", "replace")))
    return vals


def _flatten(prefix: str, node, out: list) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _flatten(f"{prefix}.{k}" if prefix else str(k), v, out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _flatten(f"{prefix}[{i}]", v, out)
    elif node is not None:
        out.append((prefix, str(node)))


def find_sqli(values: list[tuple[str, str]]) -> dict | None:
    for name, value in values:
        for rx, label in SQLI_PATTERNS:
            if rx.search(value):
                return {"param": name, "value": value[:120], "pattern": label}
    return None


# ---------------------------------------------------------------- ownership
def ownership_mismatch(path: str, request: Request, session) -> dict | None:
    """Logged-in user asks for a record owner (roll / userId) that is not theirs."""
    param = config.OWNER_PARAMS.get(path)
    if not param or not session:
        return None
    requested = request.query_params.get(param)
    if requested and requested.strip() != session.roll:
        return {"param": param, "requested": requested.strip(), "own": session.roll}
    return None


# ---------------------------------------------------------------- session guard (features 2 + 3)
def session_problem(session, device: str, ip: str) -> tuple[str, str] | None:
    """(code, human reason) if this session must be ended now."""
    now = time.time()
    idle = now - session.last_seen
    if session.device != device:
        return ("session_hijack", "This session was created on a different device. Session cookies are bound to "
                                  "the device that logged in, so it was ended.")
    if idle > config.IDLE_TIMEOUT_SECONDS:
        return ("idle_timeout", f"Session idle for {int(idle // 60)} min (limit {config.IDLE_TIMEOUT_SECONDS // 60} min).")
    if not session.trusted:
        if session.ip != ip:
            return ("untrusted_new_network", f"Untrusted device came back from a new network ({ip}, was {session.ip}).")
        if idle > config.UNTRUSTED_IDLE_SECONDS:
            return ("untrusted_idle", f"Untrusted device idle for {int(idle // 60)} min "
                                      f"(limit {config.UNTRUSTED_IDLE_SECONDS // 60} min).")
        if now - session.created > config.UNTRUSTED_MAX_SECONDS:
            return ("untrusted_expired", f"Untrusted-device sessions last at most {config.UNTRUSTED_MAX_SECONDS // 60} min.")
    return None
