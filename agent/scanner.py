"""Response scanner: looks at what is LEAVING the server and masks it on the fly.

For each record in a JSON response it decides: does it belong to the viewer
or to someone else? Other people's personal identifiers (by field name AND by
value pattern) are masked before the response is sent. Passwords never leave.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import config

PHONE_RX = re.compile(r"(?<!\d)[6-9]\d{9}(?!\d)")
AADHAAR_RX = re.compile(r"(?<!\d)\d{4}\s\d{4}\s\d{4}(?!\d)")
EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")


@dataclass
class RecordHit:
    record_id: str
    owner: str | None
    name: str | None
    masked: list[str] = field(default_factory=list)      # PII fields we masked
    private: list[str] = field(default_factory=list)     # private content of someone else that went out
    sample: dict = field(default_factory=dict)           # masked preview for evidence


@dataclass
class ScanResult:
    records: int = 0
    own: int = 0
    foreign: list[RecordHit] = field(default_factory=list)
    stripped_passwords: int = 0

    @property
    def masked_records(self) -> list[RecordHit]:
        return [r for r in self.foreign if r.masked]

    @property
    def private_leaks(self) -> list[RecordHit]:
        return [r for r in self.foreign if r.private]


# ---------------------------------------------------------------- masking
def mask_value(key: str, value) -> str:
    s = str(value)
    if key == "password":
        return "[removed]"
    if key == "address":
        return "[hidden by Kavach]"
    if key == "dob":
        return "••/••/" + s[:4] if len(s) >= 4 else "••••"
    if key == "aadhaar" or AADHAAR_RX.fullmatch(s):
        return "XXXX XXXX " + s.replace(" ", "")[-4:]
    if key == "email" or EMAIL_RX.fullmatch(s):
        user, _, dom = s.partition("@")
        return (user[:1] + "•••@" + dom) if dom else "•••"
    if key == "phone" or PHONE_RX.fullmatch(s):
        return s[:2] + "•" * 6 + s[-2:]
    if key == "id_card":
        return s[:4] + "••" + s[-2:]
    return "•" * min(len(s), 8)


def _pattern_pii(value: str) -> str | None:
    if AADHAAR_RX.search(value):
        return "aadhaar"
    if PHONE_RX.search(value):
        return "phone"
    if EMAIL_RX.search(value):
        return "email"
    return None


# ---------------------------------------------------------------- walking
def scan(payload, viewer: str | None, endpoint: str) -> ScanResult:
    """Mutates payload in place (masking) and returns what was found."""
    res = ScanResult()
    _walk(payload, None, viewer, endpoint, res)
    return res


def _owner_of(d: dict) -> str | None:
    for k in config.OWNER_KEYS:
        if k in d and d[k] is not None:
            return str(d[k])
    return None


def _is_record(d: dict) -> bool:
    keys = set(d)
    return bool(keys & set(config.OWNER_KEYS) or keys & config.PII_FIELDS or keys & config.PRIVATE_RECORD_FIELDS)


def _walk(node, inherited_owner, viewer, endpoint, res: ScanResult) -> None:
    if isinstance(node, list):
        for item in node:
            _walk(item, inherited_owner, viewer, endpoint, res)
    elif isinstance(node, dict):
        owner = _owner_of(node) or inherited_owner
        if _is_record(node):
            _process_record(node, owner, viewer, endpoint, res)
        else:   # envelope like {"count": .., "rows": [...]}
            for v in node.values():
                if isinstance(v, (list, dict)):
                    _walk(v, owner, viewer, endpoint, res)


def _process_record(rec: dict, owner, viewer, endpoint, res: ScanResult) -> None:
    res.records += 1
    foreign = owner is None or owner != viewer
    kind = "applicant" if "admissions" in endpoint else "record"
    rid = owner if owner else f"{kind}#{rec.get('id', '?')}"
    hit = RecordHit(record_id=rid, owner=owner, name=rec.get("name") or rec.get("student_name"))
    _mask_dict(rec, foreign, hit, res)
    if foreign:
        hit.masked = sorted(set(hit.masked))
        hit.private = sorted(set(hit.private))
        hit.sample = {k: (rec[k] if not isinstance(rec[k], (dict, list)) else "…") for k in list(rec)[:7]}
        res.foreign.append(hit)
    else:
        res.own += 1


def _mask_dict(d: dict, foreign: bool, hit: RecordHit, res: ScanResult) -> None:
    for key in list(d):
        val = d[key]
        if key in config.NEVER_SEND_FIELDS:
            d[key] = "[removed]"
            res.stripped_passwords += 1
            if foreign:
                hit.masked.append(key)
            continue
        if isinstance(val, dict):
            if foreign and key in config.PRIVATE_RECORD_FIELDS:
                hit.private.append(key)
            _mask_dict(val, foreign, hit, res)
            continue
        if isinstance(val, list):
            if foreign and key in config.PRIVATE_RECORD_FIELDS:
                hit.private.append(key)
            for item in val:
                if isinstance(item, dict):
                    _mask_dict(item, foreign, hit, res)
            continue
        if not foreign or val is None:
            continue
        if key in config.PII_FIELDS:
            d[key] = mask_value(key, val)
            hit.masked.append(key)
        elif key in config.PRIVATE_RECORD_FIELDS:
            hit.private.append(key)
        elif isinstance(val, str) and key not in ("name", "student_name"):
            kind = _pattern_pii(val)
            if kind:      # PII hiding under an unexpected field name
                d[key] = mask_value(kind, val)
                hit.masked.append(f"{key} ({kind} pattern)")
