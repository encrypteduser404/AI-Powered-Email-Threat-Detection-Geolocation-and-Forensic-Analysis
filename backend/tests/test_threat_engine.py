import unittest
from pathlib import Path

from app.services.email_parser import parse_email
from app.services.threat_engine import analyze_email


FIXTURES = Path(__file__).parent / "fixtures"


class ThreatEngineTests(unittest.TestCase):
    def load_result(self, name: str):
        return analyze_email(parse_email((FIXTURES / name).read_bytes()))

    def test_benign_email_has_low_score_and_unknown_auth(self) -> None:
        result = self.load_result("benign_email.eml")
        self.assertLessEqual(result.risk_score, 10)
        self.assertEqual(result.severity, "LOW")
        self.assertEqual(result.threat_type, "Benign / Low Risk")
        self.assertEqual(result.authentication.spf, "UNKNOWN")
        self.assertEqual(result.authentication.dmarc, "UNKNOWN")
        self.assertFalse(result.findings)
        self.assertIsNone(result.geolocation)

    def test_credential_phishing_combines_observed_signals(self) -> None:
        result = self.load_result("credential_phishing.eml")
        self.assertGreater(result.risk_score, 50)
        self.assertEqual(result.threat_type, "Credential Phishing")
        self.assertEqual(result.authentication.spf, "FAIL")
        self.assertEqual(result.authentication.dmarc, "FAIL")
        self.assertTrue(any(finding.category == "content" for finding in result.findings))
        self.assertTrue(any(finding.category == "url" for finding in result.findings))
        self.assertTrue(any(indicator.type == "IP" for indicator in result.indicators))
        self.assertTrue(result.recommendations)
        self.assertEqual(len(result.timeline), 8)

    def test_suspicious_attachment_is_not_called_malware(self) -> None:
        result = self.load_result("suspicious_attachment.eml")
        self.assertEqual(result.threat_type, "Malicious Attachment")
        self.assertTrue(any(finding.category == "attachment" for finding in result.findings))
        self.assertEqual(result.attachments[0].status, "SUSPICIOUS")
        self.assertNotIn("malware", result.findings[0].title.lower())

    def test_spoofing_mismatches_create_header_findings(self) -> None:
        result = self.load_result("spoofing_email.eml")
        self.assertEqual(result.threat_type, "Spoofing / Impersonation")
        self.assertGreaterEqual(sum(f.risk_contribution for f in result.findings if f.category == "header"), 25)
        self.assertTrue(any("Reply-To" in finding.title for finding in result.findings))
        self.assertTrue(any("Return-Path" in finding.title for finding in result.findings))

    def test_duplicate_authentication_evidence_is_not_double_counted(self) -> None:
        raw = b"From: sender@example.com\nTo: analyst@echo.local\nSubject: Auth\nAuthentication-Results: mx; spf=fail\nReceived-SPF: fail\n\nBody"
        result = analyze_email(parse_email(raw))
        self.assertEqual(result.authentication.spf, "FAIL")
        self.assertEqual(sum(f.risk_contribution for f in result.findings if f.id == "spf_explicit_failure"), 15)
        self.assertEqual(result.risk_score, 15)

    def test_structural_url_indicators_are_reported_without_fetching(self) -> None:
        result = self.load_result("credential_phishing.eml")
        self.assertEqual(result.urls[0].status, "SUSPICIOUS")
        self.assertIn("HTTP transport", result.urls[0].indicators)
        self.assertIn("Raw IP hostname", result.urls[0].indicators)
        self.assertEqual(result.urls[0].domain, "192.0.2.44")


if __name__ == "__main__":
    unittest.main()
