import unittest
from phishguard.analyzer import analyze_message

class AnalyzerTests(unittest.TestCase):
    def test_suspicious_content_is_flagged(self):
        result = analyze_message({
            "subject": "URGENT account locked",
            "sender": "IT Support <support@fake-microsoft-login.example>",
            "reply_to": "attacker@external.example",
            "body": "Verify now. Enter your password and OTP at https://fake-microsoft-login.example/login",
            "attachments": ["invoice.exe"],
        })
        self.assertIn(result.classification, {"SUSPICIOUS", "MALICIOUS"})
        self.assertGreater(result.risk_score, 0)
        self.assertTrue(result.findings)

    def test_clean_message_has_no_obvious_red_flags(self):
        result = analyze_message({
            "subject": "Weekly project update",
            "sender": "colleague@example.org",
            "body": "Please review the notes before our next meeting. Thank you.",
        })
        self.assertEqual(result.classification, "SAFE")
        self.assertEqual(result.risk_score, 0)

if __name__ == "__main__":
    unittest.main()
