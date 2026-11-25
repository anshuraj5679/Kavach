"""Portal authentication: two-step login, sessions, device IDs, the portal's own lockout.

This module is the PORTAL's auth, and it is deliberately weak (WEAK SPOT #5).
Kavach (agent/) wraps around it without changing it: it reads sessions to
check ownership and can end or freeze them, which is what a gateway in front
of a legacy portal would do.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

from fastapi import Request

SESSION_COOKIE = "nitm_session"
PENDING_COOKIE = "nitm_pending"
DEVICE_COOKIE = "kavach_device"

USN_LOCK_AFTER = 10            # wrong ID-card numbers before the portal locks the USN
USN_LOCK_SECONDS = 5 * 60

_lock = threading.Lock()


@dataclass
class Session:
    token: str
    roll: str
    device: str
    ip: str
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    trusted: bool = True          # Kavach flips this to False for never-seen devices


SESSIONS: dict[str, Session] = {}
PENDING: dict[str, dict] = {}          # step-1 passed, waiting for the ID card
USN_FAILS: dict[str, int] = {}         # roll -> wrong ID-card attempts
USN_LOCKED_UNTIL: dict[str, float] = {}


def device_of(request: Request) -> str:
    """Device ID cookie value (issued by the Kavach gateway on first visit)."""
    return getattr(request.state, "device", None) or request.cookies.get(DEVICE_COOKIE, "") or "unknown"


def ip_of(request: Request) -> str:
    return getattr(request.state, "ip", None) or (request.client.host if request.client else "0.0.0.0")


# ------------------------------------------------------------------ sessions
def create_session(roll: str, request: Request) -> Session:
    s = Session(token=secrets.token_urlsafe(24), roll=roll, device=device_of(request), ip=ip_of(request))
    with _lock:
        SESSIONS[s.token] = s
    return s


def get_session(token: str | None) -> Session | None:
    if not token:
        return None
    return SESSIONS.get(token)


def current_session(request: Request) -> Session | None:
    # WEAK SPOT #5c: the portal accepts a session cookie from any device, any
    # network, forever. No idle timeout, no device binding.
    # SAFE VERSION: s = get_session(token); reject if s.device != device_of(request)
    #               or time.time() - s.last_seen > IDLE_TIMEOUT; then s.last_seen = time.time()
    s = get_session(request.cookies.get(SESSION_COOKIE))
    if s:
        s.last_seen = time.time()
    return s


def end_session(token: str) -> Session | None:
    with _lock:
        return SESSIONS.pop(token, None)


def end_all_sessions(roll: str, except_token: str | None = None) -> int:
    with _lock:
        doomed = [t for t, s in SESSIONS.items() if s.roll == roll and t != except_token]
        for t in doomed:
            SESSIONS.pop(t, None)
    return len(doomed)


def sessions_for(roll: str) -> list[Session]:
    return [s for s in SESSIONS.values() if s.roll == roll]


# ------------------------------------------------------------------ portal lockout
def usn_locked(roll: str) -> float:
    """Seconds left on the portal's USN lock (0 = not locked)."""
    until = USN_LOCKED_UNTIL.get(roll, 0)
    left = until - time.time()
    if left <= 0 and until:
        USN_LOCKED_UNTIL.pop(roll, None)
        USN_FAILS.pop(roll, None)
    return max(0.0, left)


def record_id_card_failure(roll: str) -> int:
    # WEAK SPOT #5b: failures are counted per USN, so whoever types wrong
    # numbers locks out the REAL student. An attacker can lock anyone out.
    # SAFE VERSION: count failures per (IP, device) and throttle the attacker,
    #               never the account, e.g. fails[(ip, device)] += 1 (Kavach does this).
    with _lock:
        USN_FAILS[roll] = USN_FAILS.get(roll, 0) + 1
        n = USN_FAILS[roll]
        if n >= USN_LOCK_AFTER:
            USN_LOCKED_UNTIL[roll] = time.time() + USN_LOCK_SECONDS
    return n


def clear_usn_failures(roll: str) -> None:
    with _lock:
        USN_FAILS.pop(roll, None)
        USN_LOCKED_UNTIL.pop(roll, None)


def reset_state() -> None:
    with _lock:
        SESSIONS.clear()
        PENDING.clear()
        USN_FAILS.clear()
        USN_LOCKED_UNTIL.clear()
