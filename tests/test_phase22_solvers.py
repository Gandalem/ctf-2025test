"""Phase 22: independent original Our Lonely Dog and Trusted regressions.

Reuses the existing unittest discovery and Horoscopes Gemini parser.
Previous 21 Python test files remain unchanged. Public author write-ups
are verified; .eml and Gemini packets are SYNTHETIC local fixtures.
"""
import unittest
from email.message import EmailMessage
from pathlib import Path

from solvers import our_lonely_dog as dog, trusted, horoscopes

ROOT = Path(__file__).resolve().parents[1] / "data"
DOG = ROOT / "our_lonely_dog"
TRUSTED = ROOT / "trusted"
FLAG = "DUCTF{SYNTHETIC_DOG_FLAG}"
GEMINI_FLAG = "DUCTF{SYNTHETIC_TRUSTED_FLAG}"


class OurLonelyDogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.writeup = (DOG / "original_writeup.md").read_text(encoding="utf-8")

    def test_original_author_writeup_contract(self):
        dog.validate_original_writeup(self.writeup)
        self.assertEqual(dog.ADDRESS, "e-dog@downunderctf.com")

    def test_real_rfc5322_header_parser(self):
        original = (b"From: e-dog@downunderctf.com\r\n"
                    + b"X-FLAG: " + FLAG.encode()
                    + b"\r\nSubject: Pets\r\n\r\nHello")
        self.assertEqual(dog.solve(original, self.writeup), FLAG)

    def test_header_must_be_x_flag_not_body(self):
        raw = ("From: e-dog@downunderctf.com\r\n"
               "Subject: Hello\r\n\r\n" + FLAG).encode()
        with self.assertRaises(ValueError):
            dog.extract_flag(raw)

    def test_non_x_flag_header_is_not_accepted(self):
        raw = ("X-Comment: " + FLAG + "\r\n\r\nBody").encode()
        with self.assertRaises(ValueError):
            dog.extract_flag(raw)

    def test_folded_header_survives_rfc_parsing(self):
        raw = ("From: dog@example.invalid\r\n"
               "X-FLAG: DUCTF{SYNTHETIC_\r\n"
               " DOG_FLAG}\r\n\r\nhello").encode()
        # The email library unfolds whitespace to a space; this does not
        # turn an intentionally split token into a valid identical flag.
        with self.assertRaises(ValueError):
            dog.extract_flag(raw)

    def test_mime_nested_rfc822_header(self):
        outer = EmailMessage()
        outer["Subject"] = "forward"
        nested = EmailMessage()
        nested["X-FLAG"] = FLAG
        nested.set_content("Body has no flag")
        outer.set_content("forwarded message follows")
        outer.add_attachment(nested)
        self.assertEqual(dog.extract_flag(outer.as_bytes()), FLAG)

    def test_duplicate_identical_header_is_unambiguous(self):
        raw = ("X-FLAG: " + FLAG + "\r\n"
               "X-FLAG: " + FLAG + "\r\n\r\n").encode()
        self.assertEqual(dog.extract_flag(raw), FLAG)

    def test_conflicting_flags_rejected(self):
        raw = ("X-FLAG: " + FLAG + "\r\n"
               "X-FLAG: DUCTF{DIFFERENT_SYNTHETIC}\r\n\r\n").encode()
        with self.assertRaises(ValueError):
            dog.extract_flag(raw)

    def test_empty_and_oversized_input_rejected(self):
        for data in (b"", b"x" * (dog.MAX_EMAIL_BYTES + 1)):
            with self.assertRaises(ValueError):
                dog.extract_flag(data)

    def test_changed_original_writeup_rejected(self):
        with self.assertRaises(ValueError):
            dog.validate_original_writeup(self.writeup.replace("X-FLAG", "X-NOTE"))


class TrustedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.writeup = (TRUSTED / "original_writeup.md").read_text(encoding="utf-8")
        cls.info = trusted.parse_writeup(cls.writeup)
        cls.prompt = b"11 Moonlight reflects twice on still water\r\n"
        cls.success = ("20 text/gemini\r\n"
                       "# Admin Panel\r\n" + GEMINI_FLAG + "\r\n").encode()

    def test_real_author_port_and_phrase(self):
        self.assertEqual(self.info.port, 30063)
        self.assertEqual(self.info.phrase, "Moonlight reflects twice on still water")
        self.assertEqual(self.info.response, "But+ripples+show=truth%in motion")
        self.assertEqual(self.info.login_path, "/password_protected.gmi")

    def test_reuse_existing_horoscopes_gemini_parser(self):
        status, meta, _body = horoscopes.parse_response(self.prompt)
        self.assertEqual(status, 11)
        self.assertEqual(meta, self.info.phrase)

    def test_standard_gemini_input_and_exact_url_encoding(self):
        raw = trusted.build_request("chal.2025.ductf.net", self.info, self.prompt)
        self.assertEqual(
            raw,
            b"gemini://chal.2025.ductf.net:30063/password_protected.gmi?"
            b"But%2Bripples%2Bshow%3Dtruth%25in+motion\r\n",
        )

    def test_archived_malformed_1111_input_recognized(self):
        raw = b"1111 Moonlight reflects twice on still water:\r\n"
        self.assertEqual(trusted.input_prompt(raw, self.info.phrase),
                         "Moonlight reflects twice on still water")
        self.assertIn(b"?But%2Bripples", trusted.build_request(
            "chal.2025.ductf.net", self.info, raw))

    def test_wrong_prompt_rejected(self):
        with self.assertRaises(ValueError):
            trusted.build_request(
                "chal.2025.ductf.net", self.info,
                b"11 This is not the original prompt\r\n")

    def test_bad_url_and_newline_injection_rejected(self):
        with self.assertRaises(ValueError):
            trusted.build_request("bad.host\r\nINJECT", self.info, self.prompt)

    def test_saved_gemini_response_flag(self):
        self.assertEqual(trusted.verify_response(self.success), GEMINI_FLAG)

    def test_invalid_gemini_status_cannot_pass(self):
        with self.assertRaises(ValueError):
            trusted.verify_response(b"59 Bad Request\r\n")
        with self.assertRaises(ValueError):
            trusted.verify_response(b"51 Not Found\r\n")

    def test_no_flag_in_body_rejected(self):
        with self.assertRaises(ValueError):
            trusted.verify_response(b"20 text/gemini\r\nEmpty admin panel")

    def test_reconstruct_original_offline_flow(self):
        port, request, flag = trusted.solve_offline(
            self.writeup, self.prompt, self.success)
        self.assertEqual(port, 30063)
        self.assertIn(b"%25in+motion", request)
        self.assertEqual(flag, GEMINI_FLAG)

    def test_original_writeup_change_detected(self):
        with self.assertRaises(ValueError):
            trusted.parse_writeup(self.writeup.replace(
                "port is 30063", "port is unknown"))


if __name__ == "__main__":
    unittest.main()
