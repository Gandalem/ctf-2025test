"""Phase 10 independent regression suite: real Flask session replay and CMAC.

Preserve previous 9 test modules, 18 solvers and fixture layout unchanged.
Never contact non-local services or submit any real contest credentials.
"""
import re
import unittest
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from solvers import stonks, speak_friend_enter as speak

DATA = Path(__file__).resolve().parents[1] / "data"


class StonksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = DATA / "stonks"
        cls.src_file = cls.root / "stonks.py"
        cls.templates = cls.root / "templates"
        cls.source = cls.src_file.read_text(encoding="utf-8")

    def test_original_source_contract(self):
        stonks.check_source(self.source)

    def test_authentic_original_routes_replay_cookie(self):
        amount, count, marker = stonks.replay_old_currency_session(
            self.src_file, self.templates,
            marker="DUCTF{TESTING_ORIGINAL_FLASK_APP}",
        )
        self.assertGreater(amount, 1_000_000_000_000)
        self.assertGreaterEqual(count, 2)
        self.assertEqual(marker, "DUCTF{TESTING_ORIGINAL_FLASK_APP}")

    def test_threshold_cannot_be_reached_in_one_replay(self):
        with self.assertRaisesRegex(ValueError, "rich threshold"):
            stonks.replay_old_currency_session(
                self.src_file, self.templates, attempts=1,
            )

    def test_missing_template_directory(self):
        with self.assertRaisesRegex(ValueError, "template"):
            stonks.load_original_app(self.src_file, DATA / "unknown-templates",
                                     "DUCTF{LOCAL_TEST}")

    def test_malformed_synthetic_flag_rejected(self):
        with self.assertRaises(ValueError):
            stonks.load_original_app(self.src_file, self.templates,
                                     "not a valid marker")

    def test_changed_source_rejected(self):
        changed = self.source.replace(
            'old_currency = session["currency"]',
            'old_currency = user_currencies[u]',
        )
        with self.assertRaisesRegex(ValueError, "conversion"):
            stonks.check_source(changed)


class SpeakFriendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src_file = DATA / "speak_friend_server.py"
        cls.source = cls.src_file.read_text(encoding="utf-8")

    def test_original_server_gate_contract(self):
        speak.check_source(self.source)

    def test_recover_original_fixed_mac(self):
        self.assertEqual(
            speak.parse_target_mac(self.source).hex(),
            "9d4dfd27cb483aa0cf623e43ff3d3432"
        )

    def test_forged_modulus_passes_original_cmac_and_size_gate(self):
        # Fixed prefix yields reproducible output, not a hard-coded solution.
        prefix = bytes([0xFF]) + bytes(range(239))
        candidate = speak.forge_public_modulus(self.source, prefix=prefix)
        self.assertEqual(candidate.bit_length(), 2048)
        self.assertTrue(speak.verify_key_gate(self.source, candidate))

    def test_repeated_cmac_forgery_with_distinct_prefixes(self):
        target = speak.parse_target_mac(self.source)
        for fill in (b"\x00", b"\x7f", b"\xfe"):
            forged = speak.forge_cmac_message(b"\xff" * 16 + fill * 224, target)
            self.assertEqual(speak.cmac(forged), target)
            self.assertEqual(len(forged), 256)

    def test_normal_modulus_does_not_match_target(self):
        n = (1 << 2047) + 65537
        self.assertFalse(speak.verify_key_gate(self.source, n))

    def test_small_candidate_rejected(self):
        with self.assertRaisesRegex(ValueError, "240-byte"):
            speak.forge_public_modulus(self.source, prefix=b"\xff" * 16)

    def test_invalid_key_or_tag_rejected(self):
        with self.assertRaises(ValueError):
            speak.forge_cmac_message(b"\x00" * 16, b"bad-tag")
        with self.assertRaises(ValueError):
            speak.forge_cmac_message(b"\x00" * 16, b"\x00" * 16, key=b"bad")

    def test_changed_source_rejected(self):
        changed = self.source.replace(
            "public_key.bit_length() != 2048",
            "public_key.bit_length() != 1024",
        )
        with self.assertRaises(ValueError):
            speak.check_source(changed)

    def test_rsa_signature_verifier_with_generated_synthetic_key(self):
        # This demonstrates the *separate* RSA requirement with a known
        # private key. The forged CMAC-valid public modulus from above has
        # no known private key and is NOT claimed fully solved.
        rsa = RSA.generate(2048)
        challenge = b"controlled synthetic test"
        digest = int.from_bytes(SHA512.new(challenge).digest(), "big")
        private_signature = pow(digest, rsa.d, rsa.n)
        self.assertTrue(speak.verify_signature(rsa.n, challenge, private_signature))
        self.assertFalse(speak.verify_signature(rsa.n, b"wrong", private_signature))

    def test_forged_mac_does_not_imply_valid_rsa_signature(self):
        n = speak.forge_public_modulus(
            self.source, prefix=b"\xff" + b"\x01" * 239)
        self.assertTrue(speak.verify_key_gate(self.source, n))
        self.assertFalse(speak.verify_signature(n, b"any challenge", 1))


if __name__ == "__main__":
    unittest.main()
