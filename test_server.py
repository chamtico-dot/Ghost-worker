import json
import struct
import tempfile
import threading
import unittest
from datetime import timedelta
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener
import zlib

import server


class GhostWorkerServerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_database = server.DATABASE
        self.previous_iterations = server.PASSWORD_ITERATIONS
        server.DATABASE = Path(self.temp_dir.name) / "test.sqlite3"
        server.PASSWORD_ITERATIONS = 1_000
        server.init_db()
        self.httpd = ThreadlessTestServer(("127.0.0.1", 0), server.GhostWorkerHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()))

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.DATABASE = self.previous_database
        server.PASSWORD_ITERATIONS = self.previous_iterations
        self.temp_dir.cleanup()

    def request(self, method, path, payload=None, csrf_token=None):
        headers = {}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token
        request = Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def request_image(self, path, image_data, csrf_token):
        request = Request(self.base_url + path, data=image_data, headers={
            "Content-Type": "image/png",
            "X-CSRF-Token": csrf_token,
        }, method="POST")
        try:
            with self.opener.open(request) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    @staticmethod
    def sample_png():
        def chunk(chunk_type, data):
            return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)

        header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"")

    def login(self, email, password):
        status, response = self.request("POST", "/api/login", {"email": email, "password": password})
        self.assertEqual(status, 200)
        return response["csrfToken"]

    def test_seeded_passwords_are_hashed(self):
        with server.connect_db() as db:
            row = db.execute("SELECT password_hash FROM users WHERE email = ?", ("admin@kiu",)).fetchone()
        self.assertNotEqual(row["password_hash"], "hr")
        self.assertTrue(server.verify_password("hr", row["password_hash"]))
        self.assertFalse(server.verify_password("wrong-password", row["password_hash"]))

    def test_stay_signed_in_extends_session_expiry(self):
        status, _ = self.request("POST", "/api/login", {
            "email": "admin@kiu",
            "password": "hr",
            "staySignedIn": True,
        })
        self.assertEqual(status, 200)
        with server.connect_db() as db:
            expires_at = db.execute("SELECT expires_at FROM sessions").fetchone()[0]
        remaining = server.datetime.fromisoformat(expires_at) - server.now_utc()
        self.assertGreater(remaining, timedelta(days=29))

    def test_ghost_dashboard_requires_a_session(self):
        status, _ = self.request("GET", "/api/ghost/dashboard")
        self.assertEqual(status, 401)

    def test_limited_role_cannot_read_ghost_data(self):
        self.login("payroll@kiu", "payroll123")
        status, _ = self.request("GET", "/api/ghost/dashboard")
        self.assertEqual(status, 403)

    def test_ghost_worker_role_can_read_employee_profile(self):
        self.login("finance@kiu", "finance123")
        status, _ = self.request("GET", "/api/attendance")
        self.assertEqual(status, 403)
        status, response = self.request("GET", "/api/ghost/employees/KIU-0014")
        self.assertEqual(status, 200)
        employee = response["employee"]
        self.assertEqual(employee["name"], "John Doe")
        self.assertEqual(employee["department"], "Finance")
        self.assertEqual(employee["lastAttendanceDays"], 42)
        self.assertFalse(employee["biometricVerified"])
        self.assertTrue(employee["payrollActive"])
        self.assertIsNone(employee["photo"])
        self.assertIn("riskScore", employee)
        self.assertGreaterEqual(employee["riskScore"], 50)
        self.assertEqual(employee["investigationStatus"], "Open")
        self.assertIsInstance(employee["notes"], list)
        self.assertIsInstance(employee["reasons"], list)
        self.assertTrue(len(employee["reasons"]) >= 1)

    def test_investigator_profile_hides_payroll_status(self):
        self.login("investigator@kiu", "investigate")
        status, response = self.request("GET", "/api/ghost/employees/KIU-0014")
        self.assertEqual(status, 200)
        self.assertNotIn("payrollActive", response["employee"])

    def test_payroll_role_can_read_employee_profile(self):
        self.login("payroll@kiu", "payroll123")
        status, response = self.request("GET", "/api/ghost/employees/KIU-0014")
        self.assertEqual(status, 200)
        self.assertEqual(response["employee"]["department"], "Finance")

    def test_photo_upload_is_employee_privileged_and_persisted(self):
        finance_csrf = self.login("finance@kiu", "finance123")
        status, _ = self.request_image("/api/employees/KIU-0014/photo", self.sample_png(), finance_csrf)
        self.assertEqual(status, 403)

        admin_csrf = self.login("admin@kiu", "hr")
        status, _ = self.request_image("/api/employees/KIU-0014/photo", self.sample_png(), admin_csrf)
        self.assertEqual(status, 200)
        status, response = self.request("GET", "/api/ghost/employees/KIU-0014")
        self.assertEqual(status, 200)
        self.assertTrue(response["employee"]["photo"].startswith("data:image/png;base64,"))

    def test_scan_rejects_missing_csrf_token(self):
        self.login("investigator@kiu", "investigate")
        status, _ = self.request("POST", "/api/ghost/scan", {})
        self.assertEqual(status, 403)

    def test_limited_role_cannot_run_scan(self):
        csrf_token = self.login("payroll@kiu", "payroll123")
        status, _ = self.request("POST", "/api/ghost/scan", {}, csrf_token)
        self.assertEqual(status, 403)

    def test_investigator_scan_refreshes_persisted_data(self):
        csrf_token = self.login("investigator@kiu", "investigate")
        status, before = self.request("GET", "/api/ghost/dashboard")
        self.assertEqual(status, 200)
        status, result = self.request("POST", "/api/ghost/scan", {}, csrf_token)
        self.assertEqual(status, 200)
        self.assertEqual(result["summary"]["total"], 12)
        status, after = self.request("GET", "/api/ghost/dashboard")
        self.assertEqual(status, 200)
        self.assertEqual(len(after["history"]), len(before["history"]) + 1)
        self.assertEqual(len(after["alerts"]), result["summary"]["suspicious"])
        self.assertTrue(all("riskScore" in alert for alert in after["alerts"]))
        self.assertTrue(all("investigationStatus" in alert for alert in after["alerts"]))

    def test_risk_score_for_ghost_worker(self):
        score, risk, status, reasons = server.calculate_risk(
            type("R", (), {
                "last_attendance_days": 42,
                "biometric_verified": 0,
                "payroll_active": 1,
            })()
        )
        self.assertEqual(score, 75)
        self.assertEqual(risk, "Critical")
        self.assertEqual(status, "Ghost Worker")
        self.assertEqual(len(reasons), 3)

    def test_risk_score_for_inactive_only(self):
        score, risk, status, reasons = server.calculate_risk(
            type("R", (), {
                "last_attendance_days": 35,
                "biometric_verified": 1,
                "payroll_active": 1,
            })()
        )
        self.assertEqual(score, 45)
        self.assertEqual(risk, "Medium")
        self.assertEqual(status, "Inactive")

    def test_investigation_status_update(self):
        csrf = self.login("investigator@kiu", "investigate")
        status, _ = self.request(
            "POST",
            "/api/ghost/employees/KIU-0014/status",
            {"status": "Under Investigation"},
            csrf,
        )
        self.assertEqual(status, 200)
        status, response = self.request("GET", "/api/ghost/employees/KIU-0014")
        self.assertEqual(status, 200)
        self.assertEqual(response["employee"]["investigationStatus"], "Under Investigation")
        self.assertTrue(any("Under Investigation" in n["note"] for n in response["employee"]["notes"]))

    def test_investigation_status_rejects_invalid(self):
        csrf = self.login("investigator@kiu", "investigate")
        status, body = self.request(
            "POST",
            "/api/ghost/employees/KIU-0014/status",
            {"status": "Not A Real Status"},
            csrf,
        )
        self.assertEqual(status, 400)

    def test_limited_role_cannot_change_status(self):
        csrf = self.login("finance@kiu", "finance123")
        status, _ = self.request(
            "POST",
            "/api/ghost/employees/KIU-0014/status",
            {"status": "Cleared"},
            csrf,
        )
        self.assertEqual(status, 403)

    def test_add_investigation_note(self):
        csrf = self.login("investigator@kiu", "investigate")
        status, body = self.request(
            "POST",
            "/api/ghost/employees/KIU-0014/notes",
            {"note": "Spoke with department head. No activity confirmed."},
            csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["note"]["note"], "Spoke with department head. No activity confirmed.")
        status, response = self.request("GET", "/api/ghost/employees/KIU-0014")
        self.assertEqual(status, 200)
        notes = response["employee"]["notes"]
        self.assertTrue(any("department head" in n["note"] for n in notes))

    def test_status_preserved_across_rescan(self):
        csrf = self.login("investigator@kiu", "investigate")
        self.request(
            "POST",
            "/api/ghost/employees/KIU-0014/status",
            {"status": "Confirmed Ghost"},
            csrf,
        )
        self.request("POST", "/api/ghost/scan", {}, csrf)
        status, response = self.request("GET", "/api/ghost/employees/KIU-0014")
        self.assertEqual(status, 200)
        self.assertEqual(response["employee"]["investigationStatus"], "Confirmed Ghost")


class ThreadlessTestServer(server.ThreadingHTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    unittest.main()
