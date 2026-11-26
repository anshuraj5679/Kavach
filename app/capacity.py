"""Results-day server (DEMO MODE, off by default).

The demo portal runs on a fast laptop with a tiny SQLite database, so it answers in 1-2 ms
and hardly notices a few hundred students. A real campus server is different: a handful of
workers and a slower database, which is why portals fall over on results day.

When this demo mode is ON, the portal behaves like that real server:
  * only WORKERS requests are handled at once (the rest wait in line, first come first served),
  * every data API call takes about DB_MS longer, as on a busy database.

It simulates the SERVER only. Kavach's side (lanes, fair queue, flood blocking) is real and
unchanged. Switch it on from the dashboard (Portal health panel) or let the simulator's
flood / rush scenarios switch it on for their run. Off: nothing here does anything.
"""
from __future__ import annotations

import asyncio
import heapq
import itertools

from fastapi import Request

WORKERS = 8
DB_MS = 100                     # a busy campus database answers in about 100 ms
SKIP = ("/static", "/favicon", "/admin", "/api/kavach", "/kavach")


class _Slots:
    """The server's workers. Waiting requests are served by priority, then first come first served.
    With everyone at the same priority (always the case with the agent OFF) it is a plain FIFO line."""

    def __init__(self, n: int) -> None:
        self.free = n
        self.waiters: list = []                          # heap of (priority, arrival, future)
        self._seq = itertools.count()

    async def acquire(self, prio: int = 1) -> None:
        while self.waiters and self.waiters[0][2].done():
            heapq.heappop(self.waiters)                  # drop entries of requests that gave up
        if self.free > 0 and not self.waiters:
            self.free -= 1
            return
        fut = asyncio.get_running_loop().create_future()
        heapq.heappush(self.waiters, (prio, next(self._seq), fut))
        try:
            await fut
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                self.release()                           # we were handed a worker but are leaving
            else:
                fut.cancel()                             # leave a dead entry; release() skips it
            raise

    def release(self) -> None:
        while self.waiters:
            _, _, fut = heapq.heappop(self.waiters)
            if not fut.done():
                fut.set_result(True)                     # hand the worker straight to the next in line
                return
        self.free += 1


_enabled = False
_slots: _Slots | None = None
_workers, _db_ms = WORKERS, DB_MS
# Set by the agent: True for a request whose source has been marked as flooding, so a request
# already waiting for a worker is dropped instead of clogging the line.
drop_check = None
# Set by the agent: True for a request that should go ahead in the line (a logged-in student while
# the agent is ON). Without it, or with the agent OFF, the line is first come first served.
priority_check = None


def enabled() -> bool:
    return _enabled


def profile() -> tuple[int, int]:
    return _workers, _db_ms


def set_enabled(on: bool, workers: int | None = None, db_ms: int | None = None) -> None:
    """workers / db_ms: a heavier profile (the flood demo uses a small server); default otherwise."""
    global _enabled, _slots, _workers, _db_ms
    _enabled = bool(on)
    _workers = max(1, int(workers)) if workers else WORKERS
    _db_ms = max(0, int(db_ms)) if db_ms is not None else DB_MS
    _slots = _Slots(_workers) if _enabled else None


async def middleware(request: Request, call_next):
    slots = _slots
    if not _enabled or slots is None or request.url.path.startswith(SKIP):
        return await call_next(request)
    # Wait for a free worker: by priority (when the agent sets one), then first come first served.
    # The one waiter keeps its place in line (shield) while we check every 0.2 s whether its
    # source has been marked as flooding.
    prio = 0 if (priority_check is not None and priority_check(request)) else 1
    waiter = asyncio.ensure_future(slots.acquire(prio))
    while True:
        try:
            await asyncio.wait_for(asyncio.shield(waiter), timeout=0.2)
            break
        except asyncio.CancelledError:                   # the visitor gave up: never keep a worker for them
            waiter.cancel()
            if waiter.done() and not waiter.cancelled():
                slots.release()
            raise
        except asyncio.TimeoutError:
            if drop_check is not None and drop_check(request):
                waiter.cancel()
                if waiter.done() and not waiter.cancelled():
                    slots.release()                      # it got a worker just now: hand it back
                from starlette.responses import JSONResponse
                return JSONResponse({"blocked": True, "by": "Kavach", "code": "flood",
                                     "reason": "Too many requests from your connection."}, status_code=429)
    try:                                                 # a worker is busy for the whole request
        if request.url.path.startswith("/api/"):
            await asyncio.sleep(_db_ms / 1000)           # the slower database of a real server
        return await call_next(request)
    finally:
        slots.release()
