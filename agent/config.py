"""Kavach configuration: every threshold and palette token lives here.

Rules decide, the AI explains: these numbers are the ONLY thing that decides
whether a request is allowed, masked or blocked. The LLM never sees a request.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
LEDGER_DB = DATA_DIR / "ledger.db"

# ---------------------------------------------------------------- detection
WINDOW_SECONDS = 300            # sliding window for per-actor counters
FOREIGN_RECORD_LIMIT = 3        # other people's records an actor may see before being blocked
ROW_SPIKE_LIMIT = 100           # rows in ONE response that count as a mass dump (response is stopped)
FAILED_LOGIN_LIMIT = 5          # wrong tries per IP + device before Kavach blocks that device
SHARED_IP_LOGIN_LIMIT = 3       # fewer tries for other devices on an IP that already has a blocked device
IP_FAILED_LOGIN_CEILING = 20    # all devices on one IP combined (stops cookie-dropping attackers)
PORTAL_USN_LOCK_AFTER = 10      # the portal's own (bad) lock: it locks the USN, i.e. the victim
RECEIPT_IDOR_LIMIT = 2          # foreign receipt attempts before the actor is blocked (each one is refused)

BLOCK_SECONDS = 15 * 60         # how long an IP + device stays blocked
FREEZE_SECONDS = 30 * 60        # how long a frozen account needs re-verification

# session guard (features 2 and 3)
IDLE_TIMEOUT_SECONDS = 10 * 60          # any session
UNTRUSTED_IDLE_SECONDS = 3 * 60         # session on a device the student never confirmed
UNTRUSTED_MAX_SECONDS = 15 * 60         # hard cap on an untrusted-device session

# endpoints where a single foreign record is never acceptable (financial documents)
ZERO_TOLERANCE_ENDPOINTS = {"/api/fees/receipt"}

# endpoints that take a record owner in the query string, and the parameter name
OWNER_PARAMS = {
    "/api/results": "roll",
    "/api/fees/receipt": "userId",
}

# login endpoints whose 401 responses count as failed logins
LOGIN_ENDPOINTS = {"/api/auth/step1", "/api/auth/step2"}

# paths the agent never inspects (its own dashboard and static assets)
EXEMPT_PREFIXES = ("/admin", "/static", "/api/kavach", "/kavach", "/favicon")

# ---------------------------------------------------------------- data classes
# Personal identifiers: masked on the fly when they belong to someone else.
PII_FIELDS = {"phone", "aadhaar", "address", "dob", "email", "password", "id_card"}
# Never leave the server, not even to the owner.
NEVER_SEND_FIELDS = {"password"}
# Private record content: cannot be masked without breaking the feature, so it
# is protected by ownership rules instead. Seeing someone else's = a leak.
PRIVATE_RECORD_FIELDS = {"sgpa", "marks", "semesters", "amount", "receipt_no", "challan_no", "puc_marks"}
OWNER_KEYS = ("roll", "userId", "student_roll")

# ---------------------------------------------------------------- risk weights
RISK_WEIGHTS = {
    "sqli": 90,
    "ownership_mismatch": 25,
    "foreign_over_limit": 70,
    "receipt_idor": 60,
    "mass_dump": 65,
    "pii_masked": 10,
    "failed_login": 8,
    "login_flood": 62,
    "session_hijack": 70,
    "untrusted_expired": 20,
    "anomaly": 15,
}
SEVERITY_BANDS = [(80, "critical"), (60, "high"), (35, "medium"), (0, "low")]

# ---------------------------------------------------------------- explainer
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
LLM_MODEL = os.environ.get("LLM_MODEL", "").strip()
LLM_TIMEOUT_SECONDS = 45

# ---------------------------------------------------------------- palette tokens
# Mirrors static/portal.css and static/dashboard.css (the CSS variables are the
# source the browser uses; these are here so server-rendered pages agree).
PORTAL_PALETTE = {
    "primary": "#0F3D2E", "secondary": "#164E3B", "accent": "#C99A2E",
    "surface": "#FFFFFF", "bg": "#F6F5EF", "border": "#E3E1D6",
    "text": "#1D2B24", "muted": "#6B766F",
}
DASHBOARD_PALETTE = {
    "bg": "#0D1412", "panel": "#141E1B", "border": "#22302B",
    "text": "#DFE9E4", "muted": "#8AA198",
    "danger": "#E24B4A", "danger_bg": "#3A1414",
    "safe": "#6FCF97", "safe_strong": "#1F8F55",
    "high": "#E6A23C",
}
