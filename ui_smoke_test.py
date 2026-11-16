import os
import unittest

from playwright.sync_api import sync_playwright


BASE_URL = os.environ.get("GHOST_WORKER_URL", "http://127.0.0.1:8080")


class DashboardUiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def open_page(self, width=1280, height=900):
        context = self.browser.new_context(viewport={"width": width, "height": height})
        page = context.new_page()
        page.goto(BASE_URL, wait_until="networkidle")
        return context, page

    def login(self, page, email, password):
        page.locator("#login-email").fill(email)
        page.locator("#login-password").fill(password)
        page.locator("#login-form button[type=submit]").click()
        page.locator("#dashboard-shell").wait_for(state="visible")

    def test_finance_navigation_is_role_filtered(self):
        context, page = self.open_page()
        try:
            self.login(page, "finance@kiu", "finance123")
            self.assertTrue(page.locator('a[data-nav="ghost-workers"]').is_visible())
            self.assertTrue(page.locator('a[data-nav="payroll"]').is_visible())
            self.assertFalse(page.locator('a[data-nav="attendance"]').is_visible())
        finally:
            context.close()

    def test_ghost_alert_opens_employee_profile(self):
        context, page = self.open_page()
        try:
            self.login(page, "investigator@kiu", "investigate")
            page.locator('a[data-nav="ghost-workers"]').click()
            view_button = page.locator('.ghost-table tbody button[data-ghost-action="view"]').first
            view_button.wait_for(state="visible")
            view_button.click()
            page.locator("#detail-modal").wait_for(state="visible")
            self.assertEqual(page.locator("#modal-title").inner_text(), "Employee profile")
            facts = page.locator("#modal-content dt").all_inner_texts()
            self.assertIn("Department", facts)
            self.assertIn("Biometric verification", facts)
        finally:
            context.close()

    def test_mobile_dashboard_has_no_horizontal_overflow(self):
        context, page = self.open_page(width=390, height=844)
        try:
            self.login(page, "admin@kiu", "hr")
            dimensions = page.evaluate("() => ({viewport: window.innerWidth, document: document.documentElement.scrollWidth})")
            self.assertLessEqual(dimensions["document"], dimensions["viewport"] + 1, dimensions)
        finally:
            context.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
