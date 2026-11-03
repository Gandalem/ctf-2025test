"""New tests are kept separate and reuse source fixtures in existing data/.

The original tests/test_solvers.py remains unchanged, and the repository's
existing unittest discovery runs both old and new suites.
"""
import shutil
import unittest
from pathlib import Path
from solvers import zeus, skippy

DATA = Path(__file__).resolve().parents[1] / "data"

class ZeusTests(unittest.TestCase):
    def setUp(self):
        self.source = (DATA / "zeus_main.c").read_text(encoding="utf-8")

    def test_official_challenge_output(self):
        self.assertEqual(
            zeus.solve(self.source),
            "DUCTF{king_of_the_olympian_gods_and_god_of_the_sky}",
        )

    def test_xor_roundtrip(self):
        sample, key = b"example sample text", b"key"
        encrypted = zeus.repeated_key_xor(sample, key)
        self.assertNotEqual(sample, encrypted)
        self.assertEqual(sample, zeus.repeated_key_xor(encrypted, key))

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            zeus.repeated_key_xor(b"x", b"")

    def test_missing_fixture_data(self):
        with self.assertRaises(ValueError):
            zeus.solve("int main(void) { return 0; }")

@unittest.skipUnless(shutil.which("openssl"), "OpenSSL command not found")
class SkippyTests(unittest.TestCase):
    def setUp(self):
        self.source = (DATA / "skippy_main.c").read_text(encoding="utf-8")

    def test_official_challenge_output(self):
        self.assertEqual(
            skippy.solve(self.source),
            "DUCTF{There_echoes_a_chorus_enending_and_wild_Laughter_and_gossip_unruly_and_piled}",
        )

    def test_key_iv_deobfuscation(self):
        encoded_key = skippy.c_array(self.source, "key")
        encoded_iv = skippy.c_array(self.source, "iv")
        self.assertEqual(len(skippy.recover_material(encoded_key)), 16)
        self.assertEqual(len(skippy.recover_material(encoded_iv)), 16)
        self.assertEqual(skippy.recover_material(bytes([0x82] * 16)), b"A" * 16)

    def test_reject_short_key(self):
        with self.assertRaises(ValueError):
            skippy.recover_material(b"\x02" * 15)

    def test_reject_missing_ciphertext(self):
        with self.assertRaises(ValueError):
            skippy.solve("int main(void) { return 0; }")

if __name__ == "__main__":
    unittest.main()
