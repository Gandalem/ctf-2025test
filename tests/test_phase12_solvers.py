"""Phase 12 separate regression module for Gomail and Certvalidated.

Gomail additionally runs two integration tests written in Go against the
unaltered original Gin routes and session decoder. All previous unittest
modules and original challenge files remain unchanged.
"""
import base64
import struct
import unittest
from pathlib import Path
from solvers import gomail, certvalidated

DATA = Path(__file__).resolve().parents[1] / "data"


class GomailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.claims_source = (DATA / "gomail/app/session/claims.go").read_text(encoding="utf-8")
        cls.handlers_source = (DATA / "gomail/app/handlers.go").read_text(encoding="utf-8")

    def test_original_go_source_and_overflow(self):
        email = gomail.solve(self.claims_source, self.handlers_source)
        self.assertEqual(len(email), 65552)
        self.assertTrue(email.startswith("mc-fat@monke.zip"))
        self.assertNotIn("\x00", email)

    def test_actual_serialized_claims(self):
        email = gomail.make_email()
        raw = gomail.original_claims_serializer(email, 123456789, False)
        self.assertEqual(raw[:2], struct.pack("<H", 16))
        self.assertEqual(
            gomail.original_claims_deserializer(raw),
            ("mc-fat@monke.zip", int.from_bytes(b"z" * 8, "little"), True),
        )

    def test_unmodified_guest_is_not_admin(self):
        guest = gomail.original_claims_serializer("guest@example.com", 123, False)
        self.assertEqual(
            gomail.original_claims_deserializer(guest),
            ("guest@example.com", 123, False),
        )

    def test_attack_does_not_require_mac_key(self):
        # The original server signs the maliciously serialized claims with
        # its own random 64-byte key. Payload generation never uses that key.
        self.assertIn("t", gomail.make_email())
        self.assertEqual(gomail.make_email()[:16], gomail.ADMIN_EMAIL)

    def test_invalid_payload_parameters(self):
        for invalid in (b"", b"\x00", b"\r", b"XX"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    gomail.make_email(filler=invalid)

    def test_reject_changed_go_source(self):
        changed = self.claims_source.replace("uint16(l)", "uint32(l)")
        with self.assertRaises(ValueError):
            gomail.solve(changed, self.handlers_source)

    def test_reject_truncated_claims(self):
        with self.assertRaises(ValueError):
            gomail.original_claims_deserializer(b"\x10\x00short")


class CertvalidatedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "certvalidated/certvalidated.py").read_text(encoding="utf-8")
        cls.root = (DATA / "certvalidated/root.crt").read_bytes()

    def test_exact_original_challenge_message(self):
        message = certvalidated.parse_message(self.source)
        self.assertIn(b"af17a1f2654d3d40", message)
        self.assertGreater(len(message), 70)

    def test_forged_certificate_passes_original_verifier(self):
        blob, statuses = certvalidated.check_original_verifier(self.source, self.root)
        self.assertTrue(all(statuses), statuses)
        self.assertGreater(len(blob), 500)
        self.assertEqual(base64.b64decode(base64.b64encode(blob)), blob)

    def test_missing_original_message_is_rejected(self):
        with self.assertRaises(ValueError):
            certvalidated.parse_message("print('no challenge')")

    def test_invalid_root_is_rejected(self):
        with self.assertRaises(Exception):
            certvalidated.create_forged_cms(b"hello", b"not a certificate")

    def test_empty_message_is_rejected(self):
        with self.assertRaises(ValueError):
            certvalidated.create_forged_cms(b"", self.root)

    def test_cms_certificate_contains_root_signature_bytes(self):
        from cryptography import x509
        from asn1crypto import cms
        root = x509.load_pem_x509_certificate(self.root)
        blob = certvalidated.create_forged_cms(
            certvalidated.parse_message(self.source), self.root)
        content = cms.ContentInfo.load(blob)["content"]
        certificates = content["certificates"]
        self.assertEqual(len(certificates), 1)
        supplied = certificates[0].chosen
        self.assertEqual(supplied["signature_value"].native, root.signature)

if __name__ == "__main__":
    unittest.main()
