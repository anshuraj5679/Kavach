"""Portal database: SQLite schema + Faker seeding.

EVERY person in this database is invented. Faker generates names, phones,
Aadhaar-style IDs, addresses and marks from a fixed seed, so the demo is
reproducible and contains no real person's data.
"""
from __future__ import annotations

import json
import random
import sqlite3
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
PORTAL_DB = DATA_DIR / "portal.db"

SEED = 2025
N_STUDENTS = 1000
N_APPLICANTS = 1000
N_LOANS = 420
EMAIL_DOMAIN = "student.northfield.example"   # .example is reserved: never a real domain

BRANCHES = {
    "CSE": "Computer Science & Engg.",
    "ISE": "Information Science & Engg.",
    "ECE": "Electronics & Communication",
    "EEE": "Electrical & Electronics",
    "ME": "Mechanical Engineering",
    "CV": "Civil Engineering",
    "AIML": "AI & Machine Learning",
}
# Course registration for the acknowledgement form (odd semester, A.Y. 2026-27).
# Course codes, names and credits only: no student data.
REGISTRATION = {"term": "Odd Semester of A.Y. 2026-2027", "semester": 5, "stream": "B.E"}
COURSES = [
    ("Professional Core Courses", "BCS501", "Software Engineering & Project Management", 3),
    ("Professional Core Courses", "BCS502", "Computer Networks", 4),
    ("Professional Core Courses", "BCS503", "Theory of Computation", 4),
    ("Professional Core Courses", "BCSL504", "Web Technology Laboratory", 1),
    ("Professional Core Courses", "BRMK507", "Research Methodology and IPR", 2),
    ("Professional Core Courses", "BCS506", "Mini Project", 3),
    ("Professional Core Courses", "BCSP508", "Environmental Science Project", 1),
    ("Professional Elective Courses", "BCS505B", "Artificial Intelligence", 3),
    ("Professional Open Elective Courses", "BCUK509", "Cultural", 0),
]
SUBJECTS = {
    1: ["Engineering Mathematics I", "Engineering Physics", "Basic Electrical", "C Programming", "English"],
    2: ["Engineering Mathematics II", "Engineering Chemistry", "Elements of Mechanical", "Python Lab", "Constitution of India"],
    3: ["Discrete Mathematics", "Data Structures", "Digital Logic", "Computer Organisation", "Unix Lab"],
    4: ["Probability & Statistics", "Algorithms", "Operating Systems", "Microcontrollers", "DBMS"],
}
BOOKS = [
    "Introduction to Algorithms", "Operating System Concepts", "Database System Concepts",
    "Computer Networks", "Digital Design", "Signals and Systems", "Engineering Mechanics",
    "Thermodynamics: An Engineering Approach", "The C Programming Language",
    "Clean Code", "Artificial Intelligence: A Modern Approach", "Higher Engineering Mathematics",
    "Electrical Machinery", "Strength of Materials", "Python Crash Course", "Compilers",
]

# Fixed accounts used by the README story and the attack simulator.
# Keep in sync with attacks/simulate.py.
STORY_ACCOUNTS = {
    "101": {"name": "Rahul Sharma", "branch": "CSE", "dob": date(2004, 3, 5), "id_card": "NITM240101"},
    "102": {"name": "Priya Rao", "branch": "ISE", "dob": date(2004, 8, 14), "id_card": "NITM240102"},
    "103": {"name": "Kavya Nair", "branch": "ECE", "dob": date(2004, 6, 21), "id_card": "NITM240103"},
    "104": {"name": "Arjun Mehta", "branch": "CSE", "dob": date(2004, 11, 2), "id_card": "NITM240104"},
    "105": {"name": "Sneha Patil", "branch": "AIML", "dob": date(2005, 1, 19), "id_card": "NITM240105"},
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS students (
    roll TEXT PRIMARY KEY, name TEXT, branch TEXT, email TEXT, phone TEXT,
    aadhaar TEXT, address TEXT, dob TEXT, password TEXT, id_card TEXT
);
CREATE TABLE IF NOT EXISTS results (
    roll TEXT, semester INTEGER, sgpa REAL, marks TEXT,
    PRIMARY KEY (roll, semester)
);
CREATE TABLE IF NOT EXISTS library (
    id INTEGER PRIMARY KEY, roll TEXT, student_name TEXT, phone TEXT,
    aadhaar TEXT, address TEXT, book TEXT, due TEXT
);
CREATE TABLE IF NOT EXISTS applicants (
    id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT,
    puc_marks REAL, branch TEXT, status TEXT
);
CREATE TABLE IF NOT EXISTS fees (
    id INTEGER PRIMARY KEY, roll TEXT, challan_no TEXT, amount INTEGER,
    mode TEXT, date TEXT, receipt_no TEXT
);
"""


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(PORTAL_DB, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def dob_password(d: date) -> str:
    """Default password = date of birth as DDMMYYYY (weak on purpose, see WEAK SPOT #5)."""
    return d.strftime("%d%m%Y")


def _grade_points(mark: int) -> int:
    for cutoff, gp in ((90, 10), (80, 9), (70, 8), (60, 7), (50, 6), (45, 5), (40, 4)):
        if mark >= cutoff:
            return gp
    return 0


def seed(force: bool = False) -> dict:
    """Create and fill the portal DB. Idempotent unless force=True."""
    from faker import Faker

    if PORTAL_DB.exists() and not force:
        with connect() as conn:
            if conn.execute("SELECT name FROM sqlite_master WHERE name='students'").fetchone():
                n = conn.execute("SELECT COUNT(*) FROM students").fetchone()[0]
                if n:
                    return {"students": n, "seeded": False}
    if PORTAL_DB.exists():
        PORTAL_DB.unlink()

    fake = Faker("en_IN")
    Faker.seed(SEED)
    rng = random.Random(SEED)

    def phone() -> str:
        return str(rng.choice("6789")) + "".join(str(rng.randint(0, 9)) for _ in range(9))

    def aadhaar() -> str:
        digits = str(rng.randint(2, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(11))
        return f"{digits[:4]} {digits[4:8]} {digits[8:]}"

    def address() -> str:
        return fake.address().replace("\n", ", ")

    students, results, fees = [], [], []
    used_ids = {a["id_card"] for a in STORY_ACCOUNTS.values()}
    challan_seq = 250000
    for i in range(N_STUDENTS):
        roll = str(101 + i)
        story = STORY_ACCOUNTS.get(roll)
        if story:
            name, branch, dob, id_card = story["name"], story["branch"], story["dob"], story["id_card"]
        else:
            name = fake.name()
            branch = rng.choice(list(BRANCHES))
            dob = date(2003, 1, 1) + timedelta(days=rng.randint(0, 3 * 365))
            while True:
                id_card = f"NITM{rng.randint(0, 999999):06d}"
                if id_card not in used_ids:
                    used_ids.add(id_card)
                    break
        first, *rest = name.lower().replace(".", "").split()
        email = f"{first}.{(rest[-1] if rest else 'student')}{roll}@{EMAIL_DOMAIN}"
        students.append((roll, name, branch, email, phone(), aadhaar(), address(),
                         dob.isoformat(), dob_password(dob), id_card))

        for sem in range(1, 5):
            marks = {s: rng.randint(38, 99) for s in SUBJECTS[sem]}
            sgpa = round(sum(_grade_points(m) for m in marks.values()) / len(marks), 2)
            results.append((roll, sem, sgpa, json.dumps(marks)))

        for k in range(rng.randint(2, 3)):
            challan_seq += rng.randint(1, 40)
            paid = date(2025, 7, 1) + timedelta(days=180 * k + rng.randint(0, 40))
            fees.append((roll, f"CH{challan_seq}", rng.choice([48500, 52000, 61250, 3500, 1200]),
                         rng.choice(["UPI", "NEFT", "Card", "DD"]), paid.isoformat(),
                         f"RC{rng.randint(10**7, 10**8 - 1)}"))

    by_roll = {s[0]: s for s in students}
    library = []
    loan_rolls = ["101", "102"] + rng.sample([s[0] for s in students[5:]], N_LOANS - 2)
    for lid, roll in enumerate(loan_rolls, start=1):
        s = by_roll[roll]
        due = date.today() + timedelta(days=rng.randint(-12, 45))   # always near 'now' for the demo
        library.append((lid, roll, s[1], s[4], s[5], s[6], rng.choice(BOOKS), due.isoformat()))

    applicants = []
    for aid in range(1, N_APPLICANTS + 1):
        name = fake.name()
        first = name.lower().split()[0].replace(".", "")
        applicants.append((aid, name, f"{first}{aid}@mail.example", phone(),
                           round(rng.uniform(55, 99), 1), rng.choice(list(BRANCHES)),
                           rng.choices(["Applied", "Shortlisted", "Admitted", "Waitlisted"], [5, 3, 2, 2])[0]))

    with connect() as conn:
        conn.executescript(SCHEMA)
        conn.executemany("INSERT INTO students VALUES (?,?,?,?,?,?,?,?,?,?)", students)
        conn.executemany("INSERT INTO results VALUES (?,?,?,?)", results)
        conn.executemany("INSERT INTO library VALUES (?,?,?,?,?,?,?,?)", library)
        conn.executemany("INSERT INTO applicants VALUES (?,?,?,?,?,?,?)", applicants)
        conn.executemany("INSERT INTO fees (roll, challan_no, amount, mode, date, receipt_no) VALUES (?,?,?,?,?,?)", fees)
    return {"students": len(students), "results": len(results), "library": len(library),
            "applicants": len(applicants), "fees": len(fees), "seeded": True}


def story_accounts() -> list[dict]:
    return [{"roll": r, "name": a["name"], "branch": a["branch"],
             "dob_password": dob_password(a["dob"]), "id_card": a["id_card"]}
            for r, a in STORY_ACCOUNTS.items()]


def counts() -> dict:
    with connect() as conn:
        return {
            "students": conn.execute("SELECT COUNT(*) FROM students").fetchone()[0],
            "applicants": conn.execute("SELECT COUNT(*) FROM applicants").fetchone()[0],
            "loans": conn.execute("SELECT COUNT(*) FROM library").fetchone()[0],
            "departments": len(BRANCHES),
        }
