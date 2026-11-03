"""Phase 5 independently tests new, non-duplicate original challenge fixtures."""
import shutil
import unittest
from pathlib import Path

from solvers import bilingual, corporate_cliche

DATA = Path(__file__).resolve().parents[1] / "data"


class BilingualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.py = (DATA / "bilingual_published.py").read_text(encoding="utf-8")
        cls.cpp = (DATA / "bilingual_helper.cpp").read_text(encoding="utf-8")

    def test_official_flag(self):
        password, flag = bilingual.solve(self.py, self.cpp)
        self.assertEqual(password, "Hydr0ph11na3")
        self.assertEqual(
            flag,
            "DUCTF{the_problem_with_dynamic_languages_is_you_cant_c_types}",
        )

    def test_rc4_roundtrip(self):
        message = b"cryptography test message"
        key = b"another-key"
        self.assertEqual(
            bilingual.rc4(key, bilingual.rc4(key, message)), message
        )

    def test_source_missing_key(self):
        with self.assertRaisesRegex(ValueError, "KEY"):
            bilingual.solve("FLAG='Zm9v'", self.cpp)

    def test_invalid_embedded_expression(self):
        bad_source = self.cpp.replace("0xd0,0xe9", "0x00,0x00", 1)
        with self.assertRaises(ValueError):
            bilingual.solve(self.py, bad_source)


class CorporateClicheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_file = DATA / "corporate_email_server.c"
        cls.source = cls.source_file.read_text(encoding="utf-8")

    def test_overflow_payload_structure(self):
        payload = corporate_cliche.make_payload(self.source)
        username, password = corporate_cliche.extract_credentials(self.source)
        self.assertEqual(payload[32:], username.encode() + b"\x00")
        self.assertEqual(payload[:len(password.encode())], password.encode())
        self.assertEqual(len(payload), 32 + len(username) + 1)

    def test_reject_short_buffer(self):
        with self.assertRaises(ValueError):
            corporate_cliche.make_payload(self.source, 1)

    def test_reject_unparseable_credentials(self):
        with self.assertRaisesRegex(ValueError, "admin credentials"):
            corporate_cliche.make_payload("int main() { return 0; }")

    @unittest.skipUnless(shutil.which("gcc"), "GCC required")
    def test_local_admin_session(self):
        result = corporate_cliche.run_local(self.source_file)
        self.assertIn("Admin login successful", result)
        self.assertIn("CTF_ADMIN_SESSION_REACHED", result)


if __name__ == "__main__":
    unittest.main()
