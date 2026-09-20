import hashlib
import unittest
from pathlib import Path

from app.services.email_parser import parse_email


FIXTURES = Path(__file__).parent / "fixtures"


class EmailParserTests(unittest.TestCase):
    def read_fixture(self, name: str) -> bytes:
        return (FIXTURES / name).read_bytes()

    def test_plain_metadata_and_urls(self) -> None:
        result = parse_email(self.read_fixture("simple_plain.eml"))
        self.assertEqual(result.metadata.from_address, "Alice Example <alice@example.com>")
        self.assertEqual(result.metadata.to, ["Analyst <analyst@echo.local>", "second@example.net"])
        self.assertEqual(result.metadata.cc, ["copy@example.org"])
        self.assertEqual(result.metadata.subject, "Plain message")
        self.assertIn("Hello analyst.", result.body.plain_text or "")
        self.assertEqual(result.statistics.url_count, 1)
        self.assertEqual(result.urls[0].domain, "example.com")
        self.assertEqual(result.attachments, [])

    def test_html_body_and_url_source(self) -> None:
        result = parse_email(self.read_fixture("html_email.eml"))
        self.assertIsNone(result.body.plain_text)
        self.assertIn("https://example.org/path", result.body.html or "")
        self.assertEqual(result.urls[0].source, "html")
        self.assertEqual(result.metadata.cc, [])

    def test_repeated_headers_and_attachments(self) -> None:
        result = parse_email(self.read_fixture("multipart_attachment.eml"))
        self.assertEqual(len(result.headers.received), 2)
        self.assertEqual(result.headers.received[0].index, 0)
        self.assertEqual(result.headers.received[0].observed_ip_candidates, ["192.0.2.10"])
        self.assertEqual(result.headers.authentication.received_spf, [])
        self.assertEqual(len(result.attachments), 2)
        expected_hash = hashlib.sha256(b"Hello attachment!").hexdigest()
        self.assertEqual(result.attachments[0].filename, "unnamed_attachment")
        self.assertEqual(result.attachments[0].sha256, expected_hash)
        self.assertEqual(result.attachments[1].filename, "notes.txt")
        self.assertEqual(result.statistics.attachment_count, 2)
        self.assertGreaterEqual(result.statistics.mime_part_count, 3)

    def test_malformed_headers_are_graceful(self) -> None:
        result = parse_email(self.read_fixture("malformed_headers.eml"))
        self.assertEqual(result.metadata.to, ["analyst@echo.local"])
        self.assertIsNotNone(result.metadata.subject)
        self.assertEqual(result.statistics.attachment_count, 0)


if __name__ == "__main__":
    unittest.main()
