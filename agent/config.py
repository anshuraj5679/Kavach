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

# Zero tolerance on ownership: the first time a logged-in student changes ?roll= / ?userId=
# in a link to someone else's record, nothing is read, the IP + device is blocked and the
# IT head and the record's owner are told. False = the older behaviour (watch, then block at
# FOREIGN_RECORD_LIMIT / RECEIPT_IDOR_LIMIT).
OWNERSHIP_ZERO_TOLERANCE = True
OWNED_RECORDS = {                                   # page or endpoint -> (incident type, what the record is)
    "/results": ("idor_scrape", "marks"),
    "/api/results": ("idor_scrape", "marks"),
    "/fees/receipt": ("receipt_idor", "fee receipt"),
    "/api/fees/receipt": ("receipt_idor", "fee receipt"),
    "/api/fees/receipt/download": ("receipt_idor", "fee receipt"),
    "/api/acknowledgement/download": ("receipt_idor", "course acknowledgement"),
    "/fees": ("idor_probe", "fee records"),
    "/api/fees": ("idor_probe", "fee records"),
    "/acknowledgement": ("idor_probe", "course acknowledgement"),
    "/api/acknowledgement": ("idor_probe", "course acknowledgement"),
    "/account": ("idor_probe", "account and security alerts"),
    "/api/me": ("idor_probe", "profile"),
    "/api/me/alerts": ("idor_probe", "account and security alerts"),
    "/library": ("idor_probe", "library records"),
    "/api/library/mine": ("idor_probe", "library records"),
}
# With zero tolerance ON these are checked on EVERY page and API, not only the ones above:
# any of these query parameters (any letter case, repeated or not) naming another student...
IDENTITY_PARAMS = {"roll", "rollno", "roll_no", "usn", "userid", "user_id", "user", "uid",
                   "student", "studentid", "student_id", "student_roll", "studentroll"}
# ...or a record number that belongs to another student (parameter -> query for its owner).
RECORD_REFS = {"challan": "SELECT roll FROM fees WHERE challan_no = ?",
               "challan_no": "SELECT roll FROM fees WHERE challan_no = ?",
               "receipt": "SELECT roll FROM fees WHERE receipt_no = ?",
               "receipt_no": "SELECT roll FROM fees WHERE receipt_no = ?"}

EXTENSION_GUARD = True          # log a student out when a browser extension touches a logged-in page
EXTENSION_BASELINE_GRACE = 3    # seconds after the baseline in which a slow-loading extension on the first page still counts as "already active"

BLOCK_SECONDS = 15 * 60        # how long an IP + device stays blocked
FREEZE_SECONDS = 30 * 60        # how long a frozen account needs re-verification

# availability shield (agent/availability.py): floods, results-day rush, health watchdog
AVAILABILITY_SHIELD = True
FLOOD_PER_SECOND = 25            # requests from one source in 1 s (a person clicking sends about 1)
FLOOD_PER_10_SECONDS = 150       # ... or in 10 s
FLOOD_BLOCK_SECONDS = 60         # how long a flooding source is refused (HTTP 429)
# Requests WITHOUT a device cookie are counted together per IP (bots that drop cookies get a
# new device on every request). Real first-time visitors share that count only for their very
# first request, and many of them can sit behind one campus Wi-Fi IP, so the limit is higher.
FLOOD_COOKIELESS_PER_SECOND = 100
FLOOD_COOKIELESS_PER_10_SECONDS = 600
# Fair share: while the portal is busy, one source sending at least FLOOD_SHARE_MIN_RPS and taking
# FLOOD_SHARE of all traffic is a flood (300 students on separate devices are about 0.3% each).
FLOOD_BUSY_INFLIGHT = 8
FLOOD_SHARE = 0.15
FLOOD_SHARE_MIN_RPS = 10
# Too many open at once: requests from one source in progress at the same moment.
FLOOD_MAX_OPEN = 8               # a person's page has at most about 4
FLOOD_COOKIELESS_MAX_OPEN = 12   # first visits behind one campus Wi-Fi IP share this count
FLOOD_TARPIT_SECONDS = 3         # a refused flooding connection is held this long before its 429
FLOOD_TARPIT_MAX = 300           # at most this many held at once (then refused straight away)
LANES = {                        # path prefixes per lane; anything else is "standard"
    "critical": ("/api/fees", "/fees", "/api/auth", "/student/login", "/logout", "/api/me"),
    "results": ("/api/results",),
    "deferrable": ("/api/library", "/api/admissions"),
}
RUSH_ENTER_INFLIGHT = 12         # requests in progress at once that switch rush mode on
RUSH_ENTER_MS = 800              # ... or a p95 response time this slow (with real traffic)
RUSH_EXIT_INFLIGHT = 3
RUSH_CALM_SECONDS = 8            # calm this long before rush mode switches off
RUSH_MIN_SOURCES = 10            # a rush means at least this many different students (not a few bots)
RESULTS_SLOTS = 6                # results requests served at once during rush mode (the demo server has 8
                                 # workers, so 2 stay free for fees and login); the rest queue fairly
RESULTS_CACHE_SECONDS = 60       # published results do not change: serve repeats from a short cache
QUEUE_HOLD_SECONDS = 8           # a results request waits quietly in line this long before 'please wait'
HEALTH_INTERVAL = 1.0            # watchdog check every second
HEALTH_SLOW_MS = 800
HEALTH_DOWN_MS = 3000
HEALTH_HISTORY = 180             # points kept for the dashboard chart (3 minutes)

# session guard (features 2 and 3)
IDLE_TIMEOUT_SECONDS = 10 * 60          # any session
UNTRUSTED_IDLE_SECONDS = 3 * 60         # session on a device the student never confirmed
UNTRUSTED_MAX_SECONDS = 15 * 60         # hard cap on an untrusted-device session

# endpoints where a single foreign record is never acceptable (financial documents)
ZERO_TOLERANCE_ENDPOINTS = {"/api/fees/receipt", "/api/fees/receipt/download", "/api/acknowledgement/download"}

# protected downloads: only through the page's own button, with a one-time tab ticket (agent/linkguard.py)
# path -> which query parameter names the document, and the words used in messages
PROTECTED_DOWNLOADS = {
    "/api/fees/receipt/download": {"ref": "challan", "kind": "receipt", "doc": "fee receipt",
                                   "button": "Generate receipt", "page": "Fees"},
    "/api/acknowledgement/download": {"ref": "sem", "kind": "acknowledgement", "doc": "course acknowledgement",
                                      "button": "Download acknowledgement", "page": "Acknowledgement"},
}
LINK_TICKET_SECONDS = 30

# endpoints that take a record owner in the query string, and the parameter name
OWNER_PARAMS = {
    "/api/results": "roll",
    "/api/fees/receipt": "userId",
    "/api/fees/receipt/download": "userId",
    "/api/acknowledgement/download": "userId",
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
    "extension": 45,
    "download_link": 50,
    "flood": 60,
    "rush": 40,
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
