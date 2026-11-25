"""Detection engine: sliding-window counters per actor, risk score, optional anomaly model.

The risk score and severity describe HOW BAD something is. Whether to block
is decided by the hard thresholds in config.py (see gateway.py); the anomaly
model can raise a score but can never override a hard rule.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from . import config

_lock = threading.Lock()
_windows: dict[tuple, deque] = defaultdict(deque)


# ---------------------------------------------------------------- counters
def hit(kind: str, key: str, n: int = 1, tag: str | None = None) -> int:
    """Record n events of `kind` for `key`; return the count inside the window."""
    now = time.time()
    with _lock:
        dq = _windows[(kind, key)]
        for _ in range(n):
            dq.append((now, tag))
        _trim(dq, now)
        return len(dq)


def count(kind: str, key: str, window: int = config.WINDOW_SECONDS) -> int:
    now = time.time()
    with _lock:
        dq = _windows.get((kind, key))
        if not dq:
            return 0
        _trim(dq, now, window)
        return len(dq)


def distinct(kind: str, key: str) -> int:
    with _lock:
        return len({t for _, t in _windows.get((kind, key), ()) if t is not None})


def _trim(dq: deque, now: float, window: int = config.WINDOW_SECONDS) -> None:
    while dq and now - dq[0][0] > window:
        dq.popleft()


def reset() -> None:
    with _lock:
        _windows.clear()


# ---------------------------------------------------------------- scoring
def score(codes: list[str]) -> tuple[int, str]:
    """Risk 0-100 from reason codes: the strongest signal counts fully, the rest add 35%."""
    weights = sorted((config.RISK_WEIGHTS.get(c, 5) for c in codes), reverse=True)
    if not weights:
        return 0, "low"
    risk = min(100, round(weights[0] + 0.35 * sum(weights[1:])))
    return risk, severity(risk)


def severity(risk: int) -> str:
    for floor, name in config.SEVERITY_BANDS:
        if risk >= floor:
            return name
    return "low"


# ---------------------------------------------------------------- anomaly (optional)
class _Anomaly:
    """IsolationForest over per-actor request features. Degrades to 'off' without scikit-learn."""

    def __init__(self) -> None:
        self.model = None
        self.status = "off (scikit-learn not installed)"
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
        except Exception:
            return
        rng = np.random.default_rng(7)
        n = 2000
        # Synthetic "normal student" behaviour over a 5-min window:
        # [requests, foreign records seen, failed logins, distinct record owners asked for, rows in last response]
        normal = np.column_stack([
            rng.integers(1, 25, n), rng.binomial(1, 0.05, n), rng.poisson(0.3, n),
            rng.binomial(1, 0.05, n), np.minimum(rng.exponential(12, n), 60),
        ]).astype(float) + rng.normal(0, 0.15, (n, 5))
        # A sparse uniform background lets the trees split beyond the normal range,
        # so behaviour far outside it isolates quickly (IsolationForest can't extrapolate otherwise).
        background = rng.uniform([0, 0, 0, 0, 0], [200, 50, 50, 50, 1000], (60, 5))
        self.np = np
        self.model = IsolationForest(n_estimators=150, random_state=7).fit(self._x(np.vstack([normal, background])))
        self.threshold = float(np.percentile(self.model.score_samples(self._x(normal)), 1))
        self.status = "on (IsolationForest)"

    def _x(self, a):
        return self.np.log1p(self.np.clip(self.np.asarray(a, dtype=float), 0, None))

    def score(self, features: list[float]) -> float | None:
        """0 = looks like a normal student; >0 = how far beyond the 1st percentile of normal. None when off."""
        if self.model is None:
            return None
        v = float(self.model.score_samples(self._x([features]))[0])
        return round(max(0.0, (self.threshold - v) / abs(self.threshold)) * 10, 2)


ANOMALY = _Anomaly()


def actor_features(actor_key: str, roll: str | None, rows_out: int) -> list[float]:
    return [
        count("req", actor_key),
        count("foreign", roll or actor_key),
        count("fail", actor_key),
        distinct("target", roll or actor_key),
        rows_out,
    ]
