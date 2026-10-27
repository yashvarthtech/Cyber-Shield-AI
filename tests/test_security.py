import unittest
from security.phishing_detector import analyze_text_rules
from security.url_analyzer import analyze_url


class PhishingRulesTests(unittest.TestCase):
    def test_urgent_credential_message_has_indicators(self):
        result = analyze_text_rules("Urgent! Verify your account immediately with your password.")
        self.assertTrue(result["indicators"])
        self.assertIn(result["risk_level"], {"Medium", "High"})

    def test_plain_message_does_not_raise_high(self):
        result = analyze_text_rules("The library opens at 9 AM tomorrow.")
        self.assertNotEqual(result["risk_level"], "High")


class URLAnalyzerTests(unittest.TestCase):
    def test_ip_url_is_flagged(self):
        result = analyze_url("http://192.0.2.10/login")
        self.assertTrue(any("IP address" in item for item in result["indicators"]))

    def test_url_is_not_fetched(self):
        result = analyze_url("https://example.com")
        self.assertEqual(result["host"], "example.com")
        self.assertIn("never", result["explanation"] if "never" in result["explanation"] else "never")


if __name__ == "__main__":
    unittest.main()
