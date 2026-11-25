"""AI explainer: turns an incident + its ledger rows into a human-readable report.

The LLM only WRITES. It never decides anything, and it only ever receives
structured facts (counts, field NAMES, record ids, timestamps, the root-cause
mapping). No raw personal data values are sent. Without an API key the
built-in template writes the report, so the demo works offline.
"""
from __future__ import annotations

import json
import threading
import time

from . import config, ledger

_cache: dict[tuple[str, int], dict] = {}
_lock = threading.Lock()

# Each incident type points at the labelled weak spot that caused it.
ROOT_CAUSES = {
    "idor_scrape": {
        "weak_spot": "WEAK SPOT #1 (IDOR on results)", "file": "app/portal.py", "function": "api_results",
        "problem": "The roll number is taken from the URL (?roll=) and never compared with the logged-in student.",
        "unsafe": "roll = roll or s.roll",
        "safe": "roll = s.roll   # ignore the URL parameter; always use the session's own roll\n"
                "# or: if roll and roll != s.roll: return JSONResponse({'error': 'Forbidden'}, status_code=403)",
    },
    "private_exposure": {
        "weak_spot": "WEAK SPOT #1 (missing ownership check)", "file": "app/portal.py", "function": "api_results",
        "problem": "Records are returned by id without checking that they belong to the requester.",
        "unsafe": "roll = roll or s.roll", "safe": "roll = s.roll",
    },
    "overexposure": {
        "weak_spot": "WEAK SPOT #2 (over-exposure on library)", "file": "app/portal.py", "function": "api_library_borrowers",
        "problem": "SELECT * sends phone, Aadhaar and address to the browser; the page only needs book and due date.",
        "unsafe": 'sql = "SELECT * FROM library ORDER BY due"',
        "safe": "limit = min(limit or 20, 50)\n"
                'conn.execute("SELECT id, book, due FROM library ORDER BY due LIMIT ?", (limit,))',
    },
    "mass_dump": {
        "weak_spot": "WEAK SPOT #2 (no limit on ?limit=)", "file": "app/portal.py", "function": "api_library_borrowers",
        "problem": "There is no upper bound on how many rows one request can return, so one call dumps the table.",
        "unsafe": 'rows = conn.execute(sql).fetchall()   # no LIMIT when ?limit= is missing',
        "safe": "limit = min(limit or 20, 50)   # hard cap, plus explicit columns",
    },
    "sqli": {
        "weak_spot": "WEAK SPOT #3 (SQL injection on admissions)", "file": "app/portal.py", "function": "api_admissions_search",
        "problem": "The search text is pasted into the SQL string, so quotes in the input change the query.",
        "unsafe": "sql = f\"SELECT * FROM applicants WHERE name = '{q}' ...\"",
        "safe": 'conn.execute("SELECT id, name, branch, status FROM applicants WHERE name = ? '
                'OR name LIKE ? OR name LIKE ? LIMIT 25", (q, q + " %", "% " + q))',
    },
    "receipt_idor": {
        "weak_spot": "WEAK SPOT #4 (IDOR on fee receipts)", "file": "app/portal.py", "function": "api_fee_receipt",
        "problem": "The receipt is fetched by the userId in the URL with no ownership check, and SELECT * also returns "
                   "Aadhaar, address and the plain-text password.",
        "unsafe": 'sql = "SELECT * FROM fees f JOIN students s ON s.roll = f.roll WHERE f.roll = ?"  # ? = userId from URL',
        "safe": 'conn.execute("SELECT f.challan_no, f.amount, f.mode, f.date, f.receipt_no, s.name, s.branch '
                'FROM fees f JOIN students s ON s.roll = f.roll WHERE f.roll = ? AND f.challan_no = ?", (s.roll, challan))',
    },
    "login_attack": {
        "weak_spot": "WEAK SPOT #5 (weak auth + per-USN lockout)", "file": "app/auth.py / app/portal.py",
        "function": "record_id_card_failure, auth_step1, auth_step2",
        "problem": "Passwords are dates of birth, the second factor is the printed ID-card number, and failures are "
                   "counted per USN, so an attacker can guess credentials or lock the real student out.",
        "unsafe": "USN_FAILS[roll] += 1   # locks the victim, not the attacker",
        "safe": "fails[(ip, device)] += 1   # throttle the attacker's device, never the account\n"
                "# plus: real passwords (argon2 hashes) and an OTP as the second factor",
    },
    "session_hijack": {
        "weak_spot": "WEAK SPOT #5c (sessions not bound to a device, never expire)", "file": "app/auth.py",
        "function": "current_session",
        "problem": "The portal accepts a session cookie from any device and network, with no idle timeout.",
        "unsafe": "s = get_session(request.cookies.get(SESSION_COOKIE))",
        "safe": "if s.device != device_of(request) or time.time() - s.last_seen > IDLE_TIMEOUT: end_session(s.token)",
    },
}

TYPE_LABELS = {
    "idor_scrape": "Results scraping (IDOR)", "private_exposure": "Private record exposure",
    "overexposure": "Over-exposure of personal data", "mass_dump": "Mass data dump",
    "sqli": "SQL injection", "receipt_idor": "Fee-receipt IDOR", "login_attack": "Credential guessing / lockout attack",
    "session_hijack": "Session hijack",
}


def llm_mode() -> str:
    if config.ANTHROPIC_API_KEY:
        return f"anthropic · {config.LLM_MODEL or 'claude-opus-5-5'}"
    if config.OPENAI_API_KEY:
        return f"openai · {config.LLM_MODEL or 'gpt-4o-mini'}"
    return "template (offline)"


def facts_for(inc: dict) -> dict:
    """Structured facts only: no personal data values ever leave through here."""
    rows = ledger.leaks_for(inc["id"])
    leaked = [r for r in rows if r["outcome"] == "leaked"]
    masked = [r for r in rows if r["outcome"] == "masked"]
    fields = sorted({f for r in rows for f in r["fields"]})
    return {
        "incident_id": inc["id"], "type": inc["type"], "type_label": TYPE_LABELS.get(inc["type"], inc["type"]),
        "title": inc["title"], "severity": inc["severity"], "risk_score": inc["risk"],
        "first_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(inc["first_seen"])),
        "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(inc["last_seen"])),
        "endpoint": inc["endpoint"], "requests_seen": inc.get("requests", 0),
        "actor": {"ip": inc["actor"].get("ip"), "device": inc["actor"].get("device"),
                  "account": inc["actor"].get("roll")},
        "reasons": inc["reasons"], "action_taken": inc["action"],
        "records_leaked": inc["records_leaked"], "records_protected": inc["records_protected"],
        "leaked_records": [{"record_id": r["record_id"], "fields": r["fields"]} for r in leaked[:40]],
        "masked_record_count": len(masked), "fields_involved": fields,
        "root_cause": ROOT_CAUSES.get(inc["type"]),
    }


def report(incident_id: str) -> dict:
    inc = ledger.INCIDENTS.get(incident_id)
    if not inc:
        return {"error": "No such incident."}
    key = (incident_id, inc["version"])
    with _lock:
        if key in _cache:
            return _cache[key]
    facts = facts_for(inc)
    out = None
    if config.ANTHROPIC_API_KEY or config.OPENAI_API_KEY:
        try:
            out = _llm(facts)
        except Exception as e:      # any failure: fall back, never break the dashboard
            out = None
            ledger.event("warn", f"LLM report failed for {incident_id} ({type(e).__name__}); used template")
    if out is None:
        out = _template(facts)
    out.update({"incident_id": incident_id, "version": inc["version"], "severity": inc["severity"],
                "facts": facts})
    with _lock:
        _cache[key] = out
    return out


def clear_cache() -> None:
    with _lock:
        _cache.clear()


# ------------------------------------------------------------------------- template
def _template(f: dict) -> dict:
    rc = f["root_cause"] or {}
    a = f["actor"]
    who = f"account {a['account']} " if a.get("account") else ""
    lines = [
        f"## {f['title']}",
        f"**Type:** {f['type_label']} · **Severity:** {f['severity'].upper()} (risk {f['risk_score']}/100) · "
        f"**Incident:** {f['incident_id']}",
        "",
        "### What happened",
        f"Between {f['first_seen']} and {f['last_seen']}, {who}from IP {a.get('ip')} (device {a.get('device')}) "
        f"sent {f['requests_seen']} request(s) to `{f['endpoint']}` that Kavach flagged.",
        "",
        "### Why it was flagged",
        *[f"- {r}" for r in f["reasons"]],
        "",
        "### Impact",
        f"- Records that left the server: **{f['records_leaked']}**",
        f"- Records protected (masked, refused or stopped): **{f['records_protected']}**",
    ]
    if f["fields_involved"]:
        lines.append(f"- Fields involved: {', '.join(f['fields_involved'])}")
    if f["leaked_records"]:
        ids = ", ".join(r["record_id"] for r in f["leaked_records"][:12])
        lines.append(f"- Affected records: {ids}{' …' if len(f['leaked_records']) > 12 else ''}")
    lines += ["", "### Action taken", f"{f['action_taken']}."]
    if rc:
        lines += [
            "", "### Root cause and fix",
            f"{rc['weak_spot']} in `{rc['file']}` → `{rc['function']}`. {rc['problem']}",
            "", "Unsafe:", "```", rc["unsafe"], "```", "Fix:", "```", rc["safe"], "```",
        ]
    lines += ["", "### Next steps",
              "- Apply the fix above and redeploy; Kavach is a safety net, not a substitute.",
              "- Review the leak ledger for this incident and send the student notice if records left the server."]
    notice = None
    if f["records_leaked"]:
        ids = ", ".join(r["record_id"] for r in f["leaked_records"][:20])
        fields = sorted({x for r in f["leaked_records"] for x in r["fields"]})
        nice = {"password": "password", "aadhaar": "Aadhaar number", "phone": "phone number", "address": "home address"}
        safe = [v for k, v in nice.items() if not any(k in x for x in fields)]
        notice = "\n".join([
            "Subject: Notice about your student records",
            "",
            "Dear student,",
            "",
            f"On {f['first_seen'][:10]}, a weakness in the college portal allowed another logged-in user to view "
            f"part of your record ({', '.join(fields)}). Our security system (Kavach) detected it within seconds, "
            f"blocked the user and paused the account involved.",
            "",
            f"What was not exposed: your {', '.join(safe) if safe else 'other details'}.",
            "What we are doing: the portal flaw is being fixed, and the incident has been reported to the IT head.",
            "What you can do: nothing is required. If you notice anything unusual, contact the IT help desk.",
            "",
            "IT Security, Northfield Institute of Technology & Management",
            "",
            f"(Send one notice to each affected student: {ids})",
        ])
    return {"admin_report": "\n".join(lines), "student_notice": notice, "written_by": "template"}


# ------------------------------------------------------------------------- LLM
SYSTEM_PROMPT = """You write incident reports for Kavach, a security gateway in front of a college portal.
You receive structured facts about ONE incident as JSON. The decision to block or allow was already made by deterministic rules; you only explain it.

Write two parts, separated by a line containing exactly ===STUDENT NOTICE===

Part 1, the admin report for the college IT head, in Markdown:
## <short title>
then sections: ### What happened, ### Why it was flagged, ### Impact (exact numbers from the facts), ### Action taken, ### Root cause and fix (name the weak spot, file and function from root_cause, and show the safe code in a fenced code block), ### Next steps (2-3 bullets).

Part 2, the student notice: if records_leaked is 0, write exactly NONE. Otherwise, a short, calm, plain-language email to an affected student: what happened, which kinds of data (use fields from leaked_records), what was NOT exposed, what the college is doing, and what the student can do. Sign it "IT Security, Northfield Institute of Technology & Management". End with a line listing the record ids it must be sent to.

Use only the facts given. Do not invent names, numbers or data values. Keep the admin report under 350 words."""


def _parse(text: str, by: str) -> dict:
    admin, _, notice = text.partition("===STUDENT NOTICE===")
    notice = notice.strip()
    return {"admin_report": admin.strip(), "student_notice": None if not notice or notice.upper().startswith("NONE") else notice,
            "written_by": by}


def _llm(facts: dict) -> dict | None:
    user = "Incident facts (JSON):\n" + json.dumps(facts, indent=2)
    if config.ANTHROPIC_API_KEY:
        import anthropic

        model = config.LLM_MODEL or "claude-opus-5-5"
        client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY, timeout=config.LLM_TIMEOUT_SECONDS, max_retries=1)
        kwargs = dict(model=model, max_tokens=4000, system=SYSTEM_PROMPT,
                      messages=[{"role": "user", "content": user}])
        if model in ("claude-opus-5-5", "claude-opus-5", "claude-fable-5-2", "claude-fable-5-1", "claude-sonnet-5-5"):
            # Server-side refusal fallback: on a policy decline the API re-runs on a suitable model.
            kwargs.update(betas=["server-side-fallback-2026-07-01"], fallbacks="default", output_config={"effort": "low"})
            msg = client.beta.messages.create(**kwargs)
        else:
            msg = client.messages.create(**kwargs)
        if msg.stop_reason == "refusal":
            return None
        text = "".join(b.text for b in msg.content if b.type == "text").strip()
        return _parse(text, f"llm · {msg.model}") if text else None
    if config.OPENAI_API_KEY:
        from openai import OpenAI

        model = config.LLM_MODEL or "gpt-4o-mini"
        client = OpenAI(api_key=config.OPENAI_API_KEY, timeout=config.LLM_TIMEOUT_SECONDS)
        r = client.chat.completions.create(model=model, messages=[
            {"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}])
        text = (r.choices[0].message.content or "").strip()
        return _parse(text, f"llm · {model}") if text else None
    return None
