"""Start the Kavach demo.

    python run.py              # portal at http://127.0.0.1:8000, dashboard at /admin
    python run.py --reseed     # rebuild the fake portal database (same seed, same people)
    python run.py --accounts   # print the demo student logins
    python run.py --reset      # clear the Kavach ledger (incidents, blocks, events) before starting
"""
from __future__ import annotations

import argparse
import sys

from app import db


def main() -> None:
    ap = argparse.ArgumentParser(description="Kavach: AI data-leak guardian demo")
    ap.add_argument("--reseed", action="store_true", help="rebuild the portal database from the fixed seed")
    ap.add_argument("--accounts", action="store_true", help="print demo student accounts and exit")
    ap.add_argument("--reset", action="store_true", help="clear the Kavach ledger before starting")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--reload", action="store_true", help="auto-reload on code changes (development)")
    args = ap.parse_args()

    if args.reseed:
        print("Seeding fake data:", db.seed(force=True))
    if args.accounts:
        db.seed()
        print("\nDemo accounts (all fictional). Login = USN + date of birth (DDMMYYYY), then ID card number.\n")
        print(f"  {'USN':<6}{'Name':<16}{'Branch':<7}{'DOB password':<14}ID card")
        for a in db.story_accounts():
            print(f"  {a['roll']:<6}{a['name']:<16}{a['branch']:<7}{a['dob_password']:<14}{a['id_card']}")
        print("\n  Every other USN from 106 to 1100 also exists, with random data.\n")
        return
    if args.reset:
        from agent import ledger
        ledger.reset()
        print("Kavach ledger cleared.")

    import uvicorn
    # Bound to 127.0.0.1 only: this deliberately vulnerable portal must never be reachable from a network.
    print("\n  Portal     http://127.0.0.1:%d\n  Dashboard  http://127.0.0.1:%d/admin\n" % (args.port, args.port))
    uvicorn.run("app.main:app", host="127.0.0.1", port=args.port, reload=args.reload, log_level="warning")


if __name__ == "__main__":
    sys.exit(main())
