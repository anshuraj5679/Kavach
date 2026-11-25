"""A tiny one-page PDF writer for fee receipts (no third-party libraries).

Only what a receipt needs: filled rectangles, lines and Helvetica text.
Text is Latin-1; anything else is replaced, so use "Rs." rather than the rupee sign.
"""
from __future__ import annotations

W, H = 595, 842                      # A4 in points


def _esc(text: str) -> str:
    s = str(text).encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class Page:
    def __init__(self) -> None:
        self.ops: list[str] = []

    def rect(self, x: float, y: float, w: float, h: float, rgb: tuple[float, float, float]) -> None:
        self.ops.append(f"{rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f} rg {x} {y} {w} {h} re f")

    def line(self, x1: float, y1: float, x2: float, y2: float, rgb=(0.89, 0.88, 0.84), width: float = 1) -> None:
        self.ops.append(f"{rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f} RG {width} w {x1} {y1} m {x2} {y2} l S")

    def text(self, x: float, y: float, s: str, size: float = 11, bold: bool = False, rgb=(0.114, 0.169, 0.141)) -> None:
        font = "F2" if bold else "F1"
        self.ops.append(f"BT /{font} {size} Tf {rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f} rg {x} {y} Td ({_esc(s)}) Tj ET")

    def build(self, title: str = "Receipt") -> bytes:
        content = "\n".join(self.ops).encode("latin-1", "replace")
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W} {H}] /Contents 4 0 R "
            f"/Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>".encode(),
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
            f"<< /Title ({_esc(title)}) /Producer (Kavach demo) >>".encode(),
        ]
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
        out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
        out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info {len(objects)} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)


def fee_receipt(d: dict) -> bytes:
    green, gold, muted = (0.059, 0.239, 0.180), (0.788, 0.604, 0.180), (0.420, 0.463, 0.435)
    p = Page()
    p.rect(0, H - 110, W, 110, green)
    p.rect(0, H - 114, W, 4, gold)
    p.text(50, H - 55, "Northfield Institute of Technology & Management", 18, True, (1, 1, 1))
    p.text(50, H - 78, "Accounts section  -  Fee receipt", 11, False, (0.85, 0.9, 0.87))
    p.text(50, H - 160, "Fee receipt", 22, True)
    p.text(50, H - 180, "Computer-generated receipt. No signature required.", 10, False, muted)

    # PAID stamp
    p.rect(420, H - 185, 120, 44, (0.906, 0.957, 0.925))
    p.text(447, H - 171, "PAID", 22, True, (0.122, 0.561, 0.333))

    rows = [
        ("Receipt no.", d.get("receipt_no")), ("Challan no.", d.get("challan_no")),
        ("Student", d.get("name")), ("USN", d.get("userId")),
        ("Branch", d.get("branch_name") or d.get("branch")), ("Payment mode", d.get("mode")),
        ("Date", d.get("date")),
    ]
    y = H - 240
    for label, value in rows:
        p.text(50, y, label, 11, False, muted)
        p.text(200, y, str(value or "-"), 12, True)
        p.line(50, y - 12, 545, y - 12)
        y -= 36
    p.text(50, y - 6, "Amount paid", 12, False, muted)
    p.text(200, y - 8, f"Rs. {int(d.get('amount') or 0):,}", 20, True, green)

    p.line(50, 90, 545, 90)
    p.text(50, 70, "DEMO SITE - fictional college, fake data. Protected by Kavach.", 9, False, muted)
    return p.build(f"Fee receipt {d.get('receipt_no', '')}")


def course_acknowledgement(d: dict) -> bytes:
    """Course registration acknowledgement: student box, course tables by category, declaration."""
    green, gold, muted, ink = (0.059, 0.239, 0.180), (0.788, 0.604, 0.180), (0.420, 0.463, 0.435), (0.114, 0.169, 0.141)
    grey = (0.93, 0.93, 0.91)
    p = Page()
    p.rect(0, H - 96, W, 96, green)
    p.rect(0, H - 100, W, 4, gold)
    p.text(50, H - 48, "Northfield Institute of Technology & Management", 17, True, (1, 1, 1))
    p.text(50, H - 70, f"Course Registration Acknowledgement  -  {d['term']}", 11, False, (0.85, 0.9, 0.87))

    # student box + credit details
    y = H - 128
    p.rect(50, y - 4, 330, 20, grey)
    p.text(56, y + 2, d["name"], 11, True)
    p.rect(395, y - 4, 150, 20, grey)
    p.text(401, y + 2, "Credit details", 10, True)
    rows = [("USN", d["userId"]), ("Stream", d["stream"]), ("Department", d["branch_name"]),
            ("Semester", f"Semester {d['semester']}")]
    for i, (k, v) in enumerate(rows):
        yy = y - 22 - i * 17
        p.text(56, yy, k, 9.5, False, muted)
        p.text(140, yy, f":  {v}", 9.5, True)
    p.text(401, y - 22, f"Semester {d['semester']} : {d['total']:.2f}", 9.5)
    p.text(401, y - 73, f"Total : {d['total']:g}", 10, True)
    p.text(401, y - 90, f"Ack. no. {d['ack_no']}", 8.5, False, muted)

    # course tables
    y -= 110
    p.rect(50, y - 4, 495, 18, grey)
    p.text(56, y + 1, f"Semester {d['semester']}", 10, True)
    y -= 28
    for category, courses in d["groups"]:
        p.text(50, y, category, 11, True, green)
        y -= 18
        p.rect(50, y - 4, 495, 16, grey)
        p.text(56, y, "Course code", 9, True)
        p.text(150, y, "Course name", 9, True)
        p.text(492, y, "Credits", 9, True)
        y -= 16
        for code, name, credits in courses:
            p.text(56, y, code, 9)
            p.text(150, y, name.upper(), 9)
            p.text(500, y, f"{credits:.2f}", 9)
            p.line(50, y - 5, 545, y - 5)
            y -= 16
        y -= 12

    # signatures
    y = max(y - 30, 215)
    for x, label in ((50, "Student signature"), (232, "Faculty mentor"), (414, "Head of department")):
        p.line(x, y, x + 131, y, ink, 0.6)
        p.text(x + 8, y - 13, label, 9, True)

    # declaration
    y -= 42
    p.text(50, y, "Student declaration", 10, True)
    p.line(50, y - 6, 545, y - 6, ink, 0.6)
    lines = [
        "* I have a total of 0 backlog courses, equivalent to 0 credits.",
        f"* I have registered for a total of {d['count']} courses, equivalent to {d['total']:g} credits.",
        "* I am aware that I must maintain 85% attendance and a minimum of 40% of marks in CIE to be eligible for the SEE.",
        "* I declare that the above information is correct and supersedes all previous course registration data;",
        "   if found wrong, my registration may be cancelled.",
    ]
    for i, line in enumerate(lines):
        p.text(50, y - 22 - i * 14, line, 8.5)
    p.text(50, y - 112, f"Date : {d['generated']}", 9, True)
    p.text(430, y - 112, "Signature of student", 9, True)

    p.line(50, 50, 545, 50)
    p.text(50, 36, "DEMO SITE - fictional college, fake student data. Protected by Kavach.", 8, False, muted)
    return p.build(f"Course registration acknowledgement {d['userId']}")
