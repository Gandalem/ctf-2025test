"""Phase 4 regression tests: do not reimplement old tests or reuse solutions."""
import base64
import shutil
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from solvers import rocky, loadme

DATA = Path(__file__).resolve().parents[1] / "data"


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for Rocky")
class RockyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "rocky_main.c").read_text(encoding="utf-8")
        cls.candidates = (DATA / "rocky_candidates.txt").read_text(
            encoding="utf-8"
        ).splitlines()

    def test_official_challenge(self):
        self.assertEqual(
            rocky.solve(self.source, self.candidates),
            "DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}",
        )

    def test_hash_match_not_hardcoded(self):
        digest = rocky.parse_c_bytes(self.source, "hash")
        result = rocky.find_password(digest, self.candidates)
        self.assertEqual(len(result.encode()), 16)
        self.assertEqual(result, "emergencycall911")

    def test_wrong_wordlist_fails(self):
        with self.assertRaisesRegex(ValueError, "No candidate matches"):
            rocky.solve(self.source, ["not-it", "incorrect"])

    def test_bad_source_rejected(self):
        with self.assertRaises(ValueError):
            rocky.solve("void f() {}", self.candidates)


class LoadMeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = base64.b64decode(
            (DATA / "loadme_passwords.spm.b64").read_text(encoding="ascii")
        )

    def test_official_challenge(self):
        entries = loadme.solve(self.data, "DUCTF2025!")
        self.assertGreater(len(entries), 0)
        self.assertIn(
            "DUCTF{the_password_is_cool_but_the_flag_is_even_cooler}",
            loadme.flags_in(entries),
        )

    def test_wrong_password_rejected(self):
        with self.assertRaises(InvalidTag):
            loadme.solve(self.data, "wrong-password")

    def test_file_header_and_binary_offsets(self):
        salt, nonce, tag, cipher = loadme.load_file(self.data)
        self.assertEqual(len(salt), 32)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(len(tag), 16)
        self.assertGreater(len(cipher), 0)

    def test_invalid_magic(self):
        with self.assertRaisesRegex(ValueError, "magic"):
            loadme.load_file(b"WRONG" + self.data[5:])

    def test_truncated_file(self):
        with self.assertRaises(ValueError):
            loadme.load_file(self.data[:-3])

    def test_hash_iterations_change_key(self):
        salt, _, _, _ = loadme.load_file(self.data)
        self.assertEqual(len(loadme.derive_key("DUCTF2025!", salt)), 32)
        self.assertNotEqual(
            loadme.derive_key("DUCTF2025!", salt),
            loadme.derive_key("DUCTF2024!", salt),
        )


if __name__ == "__main__":
    unittest.main()
