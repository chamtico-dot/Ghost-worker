from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("GHOST_WORKER_DB", ROOT / ".ghost-worker.sqlite3"))
HOST = os.environ.get("GHOST_WORKER_HOST", "127.0.0.1")
PORT = int(os.environ.get("GHOST_WORKER_PORT", "8080"))
SESSION_SECONDS = 8 * 60 * 60
REMEMBER_SESSION_SECONDS = 30 * 24 * 60 * 60
PASSWORD_ITERATIONS = 310_000

INVESTIGATION_STATUSES = {
    "Open",
    "Under Investigation",
    "Confirmed Ghost",
    "Cleared",
    "False Positive",
}

ROLE_PRIVILEGES = {
    "Administrator": ["dashboard", "projects", "employees", "payroll-finance", "attendance", "ghost-workers", "approve", "investigate", "configure", "export", "user-admin"],
    "Payroll Administrator": ["dashboard", "employees", "payroll-finance", "attendance", "export"],
    "Finance Controller": ["dashboard", "payroll-finance", "ghost-workers", "approve", "export"],
    "HR Officer": ["dashboard", "projects", "employees", "attendance"],
    "Investigation Officer": ["dashboard", "ghost-workers", "investigate", "employees"],
    "Internal Auditor": ["dashboard", "ghost-workers", "payroll-finance", "export"],
}

DEMO_ACCOUNTS = [
    ("admin@kiu", "hr", "System Administrator", "Administrator"),
    ("payroll@kiu", "payroll123", "Amina Nalwoga", "Payroll Administrator"),
    ("finance@kiu", "finance123", "Joseph Okello", "Finance Controller"),
    ("hr@kiu", "hr123", "Grace Namukasa", "HR Officer"),
    ("investigator@kiu", "investigate", "Daniel Ssemwogerere", "Investigation Officer"),
    ("auditor@kiu", "audit123", "Sarah Atim", "Internal Auditor"),
]

SAMPLE_EMPLOYEES = [
    ("KIU-0014", "John Doe", "Finance", 42, 0, 1),
    ("KIU-0078", "Mary Atieno", "Human Resources", 35, 1, 1),
    ("KIU-0121", "Samuel Okello", "ICT", 31, 0, 1),
    ("KIU-0023", "Ruth Namusoke", "Academic staff", 1, 1, 1),
    ("KIU-0031", "Peter Kato", "Engineering", 2, 1, 1),
    ("KIU-0042", "Amina Nalwoga", "Administration", 1, 1, 1),
    ("KIU-0055", "David Mugisha", "ICT", 3, 1, 1),
    ("KIU-0063", "Grace Namukasa", "Human Resources", 1, 1, 1),
    ("KIU-0084", "Joseph Okello", "Finance", 4, 1, 1),
    ("KIU-0097", "Sarah Atim", "Internal Audit", 1, 1, 1),
    ("KIU-0108", "Daniel Ssemwogerere", "Compliance", 2, 1, 1),
    ("KIU-0140", "Neha Gupta", "Administration", 1, 1, 1),
]


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


@contextmanager
def connect_db():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def risk_level_from_score(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _row_get(row, *keys, default=None):
    """Read a value from a sqlite Row, mapping, or simple object."""
    for key in keys:
        value = None
        try:
            value = row[key]
        except (KeyError, IndexError, TypeError):
            value = getattr(row, key, None)
        if value is not None:
            return value
    return default


def calculate_risk(employee) -> tuple[int, str, str, list[str]]:
    """Return (score 0-100, risk_level, flag_status, reasons)."""
    days = int(_row_get(employee, "last_attendance_days", "lastAttendanceDays", default=0) or 0)
    biometric_ok = bool(_row_get(employee, "biometric_verified", "biometricVerified", default=0))
    payroll_active = bool(_row_get(employee, "payroll_active", "payrollActive", default=0))

    score = 0
    reasons: list[str] = []

    if days >= 60:
        score += 40
        reasons.append(f"No attendance activity for {days} days")
    elif days >= 30:
        score += 25
        reasons.append(f"No attendance activity for {days} days")

    if not biometric_ok:
        score += 30
        reasons.append("Biometric verification failed")

    if payroll_active and (days >= 30 or not biometric_ok):
        score += 20
        reasons.append("Payroll remains active while activity signals are weak")

    score = min(100, score)

    if not reasons:
        return 0, "Low", "Active", []

    # Flag type: stronger label when biometric fails and payroll is still paying
    if not biometric_ok and payroll_active:
        flag_status = "Ghost Worker"
    else:
        flag_status = "Inactive"

    return score, risk_level_from_score(score), flag_status, reasons


def ensure_schema(db: sqlite3.Connection) -> None:
    """Create tables and migrate older alert schemas in place."""
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
            csrf_token TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS employees (
            employee_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            last_attendance_days INTEGER NOT NULL,
            biometric_verified INTEGER NOT NULL,
            payroll_active INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts (
            employee_id TEXT PRIMARY KEY REFERENCES employees(employee_id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            risk TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            investigation_status TEXT NOT NULL DEFAULT 'Open',
            detected_at TEXT NOT NULL,
            details TEXT NOT NULL,
            updated_at TEXT,
            updated_by TEXT
        );
        CREATE TABLE IF NOT EXISTS investigation_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL REFERENCES employees(employee_id) ON DELETE CASCADE,
            author_email TEXT NOT NULL,
            author_name TEXT NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS employee_photos (
            employee_id TEXT PRIMARY KEY REFERENCES employees(employee_id) ON DELETE CASCADE,
            mime_type TEXT NOT NULL,
            image_data BLOB NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            total INTEGER NOT NULL,
            active INTEGER NOT NULL,
            suspicious INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS attendance_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT NOT NULL REFERENCES employees(employee_id) ON DELETE CASCADE,
            location TEXT NOT NULL,
            status TEXT NOT NULL,
            present_days INTEGER NOT NULL,
            absent_days INTEGER NOT NULL,
            leave_days INTEGER NOT NULL,
            overtime_hours INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS payroll_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payroll_id TEXT NOT NULL UNIQUE,
            employee_id TEXT NOT NULL REFERENCES employees(employee_id) ON DELETE CASCADE,
            period TEXT NOT NULL,
            amount INTEGER NOT NULL,
            deductions INTEGER NOT NULL,
            status TEXT NOT NULL
        );
    """)

    # Migrate older alert tables that lack the new columns
    columns = {row["name"] for row in db.execute("PRAGMA table_info(alerts)").fetchall()}
    if "risk_score" not in columns:
        db.execute("ALTER TABLE alerts ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0")
    if "investigation_status" not in columns:
        db.execute("ALTER TABLE alerts ADD COLUMN investigation_status TEXT NOT NULL DEFAULT 'Open'")
    if "updated_at" not in columns:
        db.execute("ALTER TABLE alerts ADD COLUMN updated_at TEXT")
    if "updated_by" not in columns:
        db.execute("ALTER TABLE alerts ADD COLUMN updated_by TEXT")


def init_db() -> None:
    with connect_db() as db:
        ensure_schema(db)
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            db.executemany(
                "INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)",
                [(email, hash_password(password), name, role) for email, password, name, role in DEMO_ACCOUNTS],
            )
        if db.execute("SELECT COUNT(*) FROM employees").fetchone()[0] == 0:
            db.executemany("INSERT INTO employees VALUES (?, ?, ?, ?, ?, ?)", SAMPLE_EMPLOYEES)
        if db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0:
            refresh_alerts(db, record_history=False)
        if db.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0] == 0:
            total = db.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
            for days_ago, suspicious in zip(range(6, -1, -1), [4, 4, 3, 3, 2, 3, 3]):
                scanned_at = (now_utc() - timedelta(days=days_ago)).isoformat()
                db.execute(
                    "INSERT INTO scan_history (scanned_at, total, active, suspicious) VALUES (?, ?, ?, ?)",
                    (scanned_at, total, total - suspicious, suspicious),
                )
        seed_attendance_and_payroll(db)


def seed_attendance_and_payroll(db: sqlite3.Connection) -> None:
    """Populate sample attendance and payroll rows from employees if empty."""
    employees = db.execute("SELECT employee_id, name, department, last_attendance_days, payroll_active FROM employees ORDER BY employee_id").fetchall()
    if not employees:
        return

    if db.execute("SELECT COUNT(*) FROM attendance_records").fetchone()[0] == 0:
        locations = ["Head Office", "Branch A", "Branch B", "Main Campus"]
        for index, emp in enumerate(employees):
            days = int(emp["last_attendance_days"])
            if days >= 30:
                status = "Absent"
                present, absent, leave = 12, min(10, days // 5), 2
            elif days >= 7:
                status = "Leave"
                present, absent, leave = 18, 1, 4
            else:
                status = "Present"
                present, absent, leave = 22, 1, 0
            overtime = 8 + (index % 9)
            location = locations[index % len(locations)]
            db.execute(
                """
                INSERT INTO attendance_records (
                    employee_id, location, status, present_days, absent_days, leave_days, overtime_hours
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (emp["employee_id"], location, status, present, absent, leave, overtime),
            )

    if db.execute("SELECT COUNT(*) FROM payroll_records").fetchone()[0] == 0:
        periods = ["June 2026", "May 2026", "April 2026"]
        base_amounts = {
            "Finance": 3250000,
            "Human Resources": 2890000,
            "ICT": 3100000,
            "Administration": 2750000,
            "Engineering": 3200000,
            "Academic staff": 3400000,
            "Internal Audit": 3000000,
            "Compliance": 2950000,
        }
        counter = 1
        for period_index, period in enumerate(periods):
            for emp in employees:
                amount = base_amounts.get(emp["department"], 2800000) - (period_index * 70000)
                deductions = int(amount * 0.13)
                # Pending if payroll inactive or first pending sample
                status = "Paid"
                if not emp["payroll_active"]:
                    status = "Pending"
                elif counter in (4, 13):
                    status = "Pending"
                payroll_id = f"PAY-{counter:03d}"
                db.execute(
                    """
                    INSERT INTO payroll_records (
                        payroll_id, employee_id, period, amount, deductions, status
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (payroll_id, emp["employee_id"], period, amount, deductions, status),
                )
                counter += 1


def refresh_alerts(db: sqlite3.Connection, record_history: bool) -> dict:
    employees = db.execute("SELECT * FROM employees ORDER BY employee_id").fetchall()
    detected_at = now_utc().isoformat()

    # Preserve investigation progress across rescans
    existing = {
        row["employee_id"]: dict(row)
        for row in db.execute(
            "SELECT employee_id, investigation_status, updated_at, updated_by FROM alerts"
        ).fetchall()
    }

    alerts = []
    for employee in employees:
        score, risk, flag_status, reasons = calculate_risk(employee)
        if score == 0:
            continue

        previous = existing.get(employee["employee_id"], {})
        inv_status = previous.get("investigation_status") or "Open"
        if inv_status not in INVESTIGATION_STATUSES:
            inv_status = "Open"

        alerts.append(
            (
                employee["employee_id"],
                flag_status,
                risk,
                score,
                inv_status,
                detected_at,
                "; ".join(reasons) + ".",
                previous.get("updated_at"),
                previous.get("updated_by"),
            )
        )

    db.execute("DELETE FROM alerts")
    db.executemany(
        """
        INSERT INTO alerts (
            employee_id, status, risk, risk_score, investigation_status,
            detected_at, details, updated_at, updated_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        alerts,
    )
    total = len(employees)
    summary = {"total": total, "active": total - len(alerts), "suspicious": len(alerts)}
    if record_history:
        db.execute(
            "INSERT INTO scan_history (scanned_at, total, active, suspicious) VALUES (?, ?, ?, ?)",
            (detected_at, summary["total"], summary["active"], summary["suspicious"]),
        )
    return summary


def public_user(row: sqlite3.Row) -> dict:
    short_name = row["name"].split()[0]
    return {
        "email": row["email"],
        "name": row["name"],
        "shortName": "Admin" if row["role"] == "Administrator" else short_name,
        "role": row["role"],
        "privileges": ROLE_PRIVILEGES.get(row["role"], []),
    }


def fetch_notes(db: sqlite3.Connection, employee_id: str) -> list[dict]:
    rows = db.execute(
        """
        SELECT id, author_email AS authorEmail, author_name AS authorName,
               note, created_at AS createdAt
        FROM investigation_notes
        WHERE employee_id = ?
        ORDER BY id DESC
        """,
        (employee_id,),
    ).fetchall()
    return [dict(row) for row in rows]


class GhostWorkerHandler(BaseHTTPRequestHandler):
    server_version = "GhostWorker/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.log_date_time_string()} {self.address_string()} {fmt % args}")

    def send_json(self, status: int, payload: dict, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'",
        )

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 64_000:
            raise ValueError("Request is too large")
        raw = self.rfile.read(length) if length else b"{}"
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object")
        return value

    def request_origin_is_local(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlsplit(origin)
        return parsed.netloc == self.headers.get("Host") and parsed.scheme in ("http", "https")

    def current_session(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get("gw_session")
        if not morsel:
            return None
        token_hash = hashlib.sha256(morsel.value.encode("utf-8")).hexdigest()
        with connect_db() as db:
            row = db.execute(
                """
                SELECT users.email, users.name, users.role, sessions.csrf_token, sessions.expires_at
                FROM sessions JOIN users ON users.email = sessions.email
                WHERE sessions.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if not row:
                return None
            if datetime.fromisoformat(row["expires_at"]) <= now_utc():
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                return None
            return {"user": public_user(row), "csrf": row["csrf_token"], "token_hash": token_hash}

    def require_privilege(self, privilege: str):
        session = self.current_session()
        if not session:
            self.send_json(401, {"error": "Sign in to continue"})
            return None
        if privilege not in session["user"]["privileges"]:
            self.send_json(403, {"error": "Your role is not permitted to access this resource"})
            return None
        return session

    def require_any_privilege(self, privileges: set[str]):
        session = self.current_session()
        if not session:
            self.send_json(401, {"error": "Sign in to continue"})
            return None
        if not privileges.intersection(session["user"]["privileges"]):
            self.send_json(403, {"error": "Your role is not permitted to access this resource"})
            return None
        return session

    def save_employee_photo(self, employee_id: str) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid image size"})
            return
        if length <= 0 or length > 5 * 1024 * 1024:
            self.send_json(413, {"error": "Choose an image smaller than 5 MB"})
            return
        mime_type = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
        image_data = self.rfile.read(length)
        valid_image = (
            mime_type == "image/jpeg" and image_data.startswith(b"\xff\xd8\xff")
            or mime_type == "image/png" and image_data.startswith(b"\x89PNG\r\n\x1a\n")
            or mime_type == "image/webp" and image_data.startswith(b"RIFF") and image_data[8:12] == b"WEBP"
        )
        if not valid_image:
            self.send_json(415, {"error": "Use a valid JPEG, PNG, or WebP image"})
            return
        with connect_db() as db:
            if not db.execute("SELECT 1 FROM employees WHERE employee_id = ?", (employee_id,)).fetchone():
                self.send_json(404, {"error": "Employee record not found"})
                return
            db.execute(
                """
                INSERT INTO employee_photos (employee_id, mime_type, image_data, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(employee_id) DO UPDATE SET
                    mime_type = excluded.mime_type,
                    image_data = excluded.image_data,
                    updated_at = excluded.updated_at
                """,
                (employee_id, mime_type, image_data, now_utc().isoformat()),
            )
        self.send_json(200, {"ok": True})

    def require_csrf(self, session: dict) -> bool:
        supplied = self.headers.get("X-CSRF-Token", "")
        if not self.request_origin_is_local() or not hmac.compare_digest(supplied, session["csrf"]):
            self.send_json(403, {"error": "Request verification failed"})
            return False
        return True

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/session":
            session = self.current_session()
            if not session:
                self.send_json(200, {"user": None, "csrfToken": ""})
            else:
                self.send_json(200, {"user": session["user"], "csrfToken": session["csrf"]})
            return

        if path == "/api/ghost/dashboard":
            if not self.require_privilege("ghost-workers"):
                return
            with connect_db() as db:
                summary = refresh_alerts(db, record_history=False)
                alerts = [
                    dict(row)
                    for row in db.execute(
                        """
                        SELECT employee_id AS id, employees.name, employees.department,
                               alerts.status, alerts.risk, alerts.risk_score AS riskScore,
                               alerts.investigation_status AS investigationStatus,
                               alerts.detected_at AS detected, alerts.details,
                               alerts.updated_at AS updatedAt, alerts.updated_by AS updatedBy
                        FROM alerts JOIN employees USING (employee_id)
                        ORDER BY alerts.risk_score DESC, alerts.detected_at DESC
                        """
                    ).fetchall()
                ]
                history = [
                    dict(row)
                    for row in db.execute(
                        """
                        SELECT scanned_at AS scannedAt, total, active, suspicious
                        FROM scan_history ORDER BY id DESC LIMIT 90
                        """
                    ).fetchall()
                ]
            self.send_json(200, {"summary": summary, "alerts": alerts, "history": list(reversed(history))})
            return

        if path.startswith("/api/ghost/employees/"):
            session = self.require_any_privilege({"employees", "ghost-workers"})
            if not session:
                return
            employee_id = path.removeprefix("/api/ghost/employees/")
            if not employee_id or "/" in employee_id:
                self.send_json(404, {"error": "Employee record not found"})
                return
            with connect_db() as db:
                row = db.execute(
                    """
                    SELECT employees.employee_id AS id, employees.name, employees.department,
                           employees.last_attendance_days AS lastAttendanceDays,
                           employees.biometric_verified AS biometricVerified,
                           employees.payroll_active AS payrollActive,
                           alerts.status, alerts.risk, alerts.risk_score AS riskScore,
                           alerts.investigation_status AS investigationStatus,
                           alerts.detected_at AS detected, alerts.details,
                           alerts.updated_at AS updatedAt, alerts.updated_by AS updatedBy,
                           employee_photos.mime_type AS photoMime, employee_photos.image_data AS photoData
                    FROM employees
                    LEFT JOIN alerts USING (employee_id)
                    LEFT JOIN employee_photos USING (employee_id)
                    WHERE employees.employee_id = ?
                    """,
                    (employee_id,),
                ).fetchone()
                notes = fetch_notes(db, employee_id) if row else []
            if not row:
                self.send_json(404, {"error": "Employee record not found"})
                return
            photo = None
            if row["photoData"] is not None:
                photo = f"data:{row['photoMime']};base64,{base64.b64encode(row['photoData']).decode('ascii')}"

            # Live score even if not currently in alerts table
            score, risk, flag_status, reasons = calculate_risk(row)
            employee = {
                "id": row["id"],
                "name": row["name"],
                "department": row["department"],
                "lastAttendanceDays": row["lastAttendanceDays"],
                "biometricVerified": bool(row["biometricVerified"]),
                "status": row["status"] or flag_status or "Active",
                "risk": row["risk"] or risk,
                "riskScore": row["riskScore"] if row["riskScore"] is not None else score,
                "investigationStatus": row["investigationStatus"] or "Open",
                "detected": row["detected"],
                "details": row["details"] or ("; ".join(reasons) + "." if reasons else "No active review alerts for this employee."),
                "reasons": reasons,
                "updatedAt": row["updatedAt"],
                "updatedBy": row["updatedBy"],
                "photo": photo,
                "notes": notes,
            }
            if "payroll-finance" in session["user"]["privileges"]:
                employee["payrollActive"] = bool(row["payrollActive"])
            self.send_json(200, {"employee": employee})
            return

        if path == "/api/employees":
            if not self.require_privilege("employees"):
                return
            with connect_db() as db:
                rows = []
                for row in db.execute(
                    """
                    SELECT employee_id AS id, name, department,
                           last_attendance_days AS lastAttendanceDays,
                           biometric_verified AS biometricVerified,
                           payroll_active AS payrollActive
                    FROM employees ORDER BY employee_id
                    """
                ).fetchall():
                    item = dict(row)
                    item["biometricVerified"] = bool(item["biometricVerified"])
                    item["payrollActive"] = bool(item["payrollActive"])
                    # Demo-friendly derived fields for the directory UI
                    item["email"] = f"{item['id'].lower().replace('-', '.')}@kiu.ac.ug"
                    item["designation"] = {
                        "Finance": "Finance Officer",
                        "Human Resources": "HR Officer",
                        "ICT": "Systems Analyst",
                        "Administration": "Admin Officer",
                        "Engineering": "Engineer",
                        "Academic staff": "Lecturer",
                        "Internal Audit": "Auditor",
                        "Compliance": "Compliance Officer",
                    }.get(item["department"], "Staff")
                    days = int(item["lastAttendanceDays"])
                    if days >= 30:
                        item["status"] = "Inactive"
                    elif days >= 7:
                        item["status"] = "On leave"
                    else:
                        item["status"] = "Active"
                    rows.append(item)
                departments = sorted({r["department"] for r in rows})
                summary = {
                    "total": len(rows),
                    "active": sum(1 for r in rows if r["status"] == "Active"),
                    "onLeave": sum(1 for r in rows if r["status"] == "On leave"),
                    "departments": len(departments),
                }
            self.send_json(200, {"employees": rows, "summary": summary, "departments": departments})
            return

        if path == "/api/attendance":
            session = self.require_privilege("attendance")
            if not session:
                return
            with connect_db() as db:
                rows = [
                    dict(row)
                    for row in db.execute(
                        """
                        SELECT attendance_records.employee_id AS id,
                               employees.name,
                               employees.department,
                               attendance_records.location,
                               attendance_records.status,
                               attendance_records.present_days AS present,
                               attendance_records.absent_days AS absent,
                               attendance_records.leave_days AS leave,
                               attendance_records.overtime_hours AS overtime
                        FROM attendance_records
                        JOIN employees USING (employee_id)
                        ORDER BY attendance_records.employee_id
                        """
                    ).fetchall()
                ]
                total = len(rows)
                present = sum(1 for r in rows if r["status"] == "Present")
                absent = sum(1 for r in rows if r["status"] == "Absent")
                leave = sum(1 for r in rows if r["status"] == "Leave")
                overtime = sum(int(r["overtime"]) for r in rows)
                rate = round((present / total * 100), 1) if total else 0.0
                summary = {
                    "total": total,
                    "present": present,
                    "absent": absent,
                    "leave": leave,
                    "overtime": overtime,
                    "attendanceRate": rate,
                }
            self.send_json(200, {"records": rows, "summary": summary})
            return

        if path == "/api/payroll":
            session = self.require_any_privilege({"payroll-finance", "export"})
            if not session:
                return
            with connect_db() as db:
                rows = [
                    dict(row)
                    for row in db.execute(
                        """
                        SELECT payroll_records.payroll_id AS id,
                               employees.name,
                               employees.department,
                               payroll_records.period,
                               payroll_records.amount,
                               payroll_records.deductions,
                               payroll_records.status
                        FROM payroll_records
                        JOIN employees USING (employee_id)
                        ORDER BY payroll_records.period DESC, payroll_records.payroll_id
                        """
                    ).fetchall()
                ]
                periods = sorted({r["period"] for r in rows}, reverse=True)
                departments = sorted({r["department"] for r in rows})
            self.send_json(200, {"records": rows, "periods": periods, "departments": departments})
            return

        if path.startswith("/api/"):
            self.send_json(404, {"error": "API route not found"})
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if not self.request_origin_is_local():
            self.send_json(403, {"error": "Cross-origin request rejected"})
            return

        photo_prefix = "/api/employees/"
        if path.startswith(photo_prefix) and path.endswith("/photo"):
            employee_id = path[len(photo_prefix) : -len("/photo")]
            if not employee_id or "/" in employee_id:
                self.send_json(404, {"error": "Employee record not found"})
                return
            session = self.require_privilege("employees")
            if not session or not self.require_csrf(session):
                return
            self.save_employee_photo(employee_id)
            return

        try:
            payload = self.read_json()
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "Invalid request body"})
            return

        if path == "/api/login":
            email = str(payload.get("email", "")).strip().lower()[:254]
            password = str(payload.get("password", ""))[:256]
            with connect_db() as db:
                row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                if not row or not verify_password(password, row["password_hash"]):
                    self.send_json(401, {"error": "Invalid email or password"})
                    return
                session_token = secrets.token_urlsafe(32)
                csrf_token = secrets.token_urlsafe(24)
                token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
                session_seconds = REMEMBER_SESSION_SECONDS if payload.get("staySignedIn") is True else SESSION_SECONDS
                expires_at = (now_utc() + timedelta(seconds=session_seconds)).isoformat()
                db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_utc().isoformat(),))
                db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)", (token_hash, email, csrf_token, expires_at))
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
            cookie = f"gw_session={session_token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={session_seconds}{secure}"
            self.send_json(200, {"user": public_user(row), "csrfToken": csrf_token}, {"Set-Cookie": cookie})
            return

        session = self.current_session()
        if not session:
            self.send_json(401, {"error": "Sign in to continue"})
            return
        if not self.require_csrf(session):
            return

        if path == "/api/logout":
            with connect_db() as db:
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (session["token_hash"],))
            self.send_json(200, {"ok": True}, {"Set-Cookie": "gw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
            return

        if path == "/api/ghost/scan":
            if "investigate" not in session["user"]["privileges"] and "configure" not in session["user"]["privileges"]:
                self.send_json(403, {"error": "Your role is not permitted to run scans"})
                return
            with connect_db() as db:
                summary = refresh_alerts(db, record_history=True)
            self.send_json(200, {"summary": summary, "message": "Sample employee records scanned"})
            return

        # Update investigation status
        if path.startswith("/api/ghost/employees/") and path.endswith("/status"):
            if "investigate" not in session["user"]["privileges"] and "configure" not in session["user"]["privileges"]:
                self.send_json(403, {"error": "Your role is not permitted to update investigation status"})
                return
            employee_id = path[len("/api/ghost/employees/") : -len("/status")]
            if not employee_id or "/" in employee_id:
                self.send_json(404, {"error": "Employee record not found"})
                return
            new_status = str(payload.get("status", "")).strip()
            if new_status not in INVESTIGATION_STATUSES:
                self.send_json(400, {"error": "Invalid investigation status"})
                return
            with connect_db() as db:
                exists = db.execute("SELECT 1 FROM employees WHERE employee_id = ?", (employee_id,)).fetchone()
                if not exists:
                    self.send_json(404, {"error": "Employee record not found"})
                    return
                alert = db.execute("SELECT 1 FROM alerts WHERE employee_id = ?", (employee_id,)).fetchone()
                now = now_utc().isoformat()
                actor = session["user"]["name"]
                if alert:
                    db.execute(
                        """
                        UPDATE alerts
                        SET investigation_status = ?, updated_at = ?, updated_by = ?
                        WHERE employee_id = ?
                        """,
                        (new_status, now, actor, employee_id),
                    )
                else:
                    # Create a minimal alert row so status can be tracked
                    emp = db.execute("SELECT * FROM employees WHERE employee_id = ?", (employee_id,)).fetchone()
                    score, risk, flag_status, reasons = calculate_risk(emp)
                    db.execute(
                        """
                        INSERT INTO alerts (
                            employee_id, status, risk, risk_score, investigation_status,
                            detected_at, details, updated_at, updated_by
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            employee_id,
                            flag_status if score else "Active",
                            risk,
                            score,
                            new_status,
                            now,
                            "; ".join(reasons) + "." if reasons else "Manual investigation opened.",
                            now,
                            actor,
                        ),
                    )
                # Auto-add a system note for the status change
                db.execute(
                    """
                    INSERT INTO investigation_notes (employee_id, author_email, author_name, note, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        employee_id,
                        session["user"]["email"],
                        actor,
                        f"Investigation status changed to “{new_status}”.",
                        now,
                    ),
                )
            self.send_json(200, {"ok": True, "status": new_status})
            return

        # Add investigation note
        if path.startswith("/api/ghost/employees/") and path.endswith("/notes"):
            if "investigate" not in session["user"]["privileges"] and "configure" not in session["user"]["privileges"]:
                self.send_json(403, {"error": "Your role is not permitted to add investigation notes"})
                return
            employee_id = path[len("/api/ghost/employees/") : -len("/notes")]
            if not employee_id or "/" in employee_id:
                self.send_json(404, {"error": "Employee record not found"})
                return
            note_text = str(payload.get("note", "")).strip()
            if not note_text or len(note_text) > 2000:
                self.send_json(400, {"error": "Note must be between 1 and 2000 characters"})
                return
            with connect_db() as db:
                if not db.execute("SELECT 1 FROM employees WHERE employee_id = ?", (employee_id,)).fetchone():
                    self.send_json(404, {"error": "Employee record not found"})
                    return
                now = now_utc().isoformat()
                db.execute(
                    """
                    INSERT INTO investigation_notes (employee_id, author_email, author_name, note, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (employee_id, session["user"]["email"], session["user"]["name"], note_text, now),
                )
                note_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            self.send_json(
                200,
                {
                    "ok": True,
                    "note": {
                        "id": note_id,
                        "authorEmail": session["user"]["email"],
                        "authorName": session["user"]["name"],
                        "note": note_text,
                        "createdAt": now,
                    },
                },
            )
            return

        self.send_json(404, {"error": "API route not found"})

    def serve_static(self, path: str) -> None:
        relative = "index.html" if path in ("", "/") else path.lstrip("/")
        allowed = {"index.html", "app.js", "styles.css", "role-dashboard.css", "login_tamplate.jpg"}
        if relative not in allowed:
            self.send_error(404)
            return
        file_path = ROOT / relative
        if not file_path.is_file():
            self.send_error(404)
            return
        body = file_path.read_bytes()
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
            content_type += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), GhostWorkerHandler)
    server.daemon_threads = True
    print(f"Serving Ghost Worker at http://{HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Ghost Worker server")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
