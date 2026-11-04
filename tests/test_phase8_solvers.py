"""Phase 8: independent tests for Paillier login and Gemini capsule.

This module is additive; all previous seven test suites remain unchanged.
"""
import hashlib
import re
import unittest
from pathlib import Path
from urllib.parse import urlparse

from solvers import horoscopes, yet_another_login as login

DATA = Path(__file__).resolve().parents[1] / "data"

class YetAnotherLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "yet_another_login_chall.py").read_text(encoding="utf-8")

    def test_original_challenge_interface(self):
        login.validate_source(self.source)

    def test_sha256_length_extension_multiple_lengths(self):
        for key_len in (1, 16, 32, 63):
            secret = bytes(i % 256 for i in range(key_len))
            original = b"user=user"
            suffix = b"user=admin"
            digest = hashlib.sha256(secret + original).digest()
            glue, forged = login.sha256_extend(digest, len(secret + original), suffix)
            self.assertEqual(
                forged,
                hashlib.sha256(secret + original + glue + suffix).digest()
            )

    def test_sha256_against_hashlib(self):
        for length in (0, 1, 55, 56, 63, 64, 65, 128):
            input_data = b"x" * length
            state = login.INIT
            data = input_data + login.sha_padding(len(input_data))
            for offset in range(0, len(data), 64):
                state = login.compress(state, data[offset:offset + 64])
            from struct import pack
            self.assertEqual(pack(">8I", *state), hashlib.sha256(input_data).digest())

    def test_invalid_short_hash(self):
        with self.assertRaises(ValueError):
            login.sha256_extend(b"invalid", 21, b"suffix")

    def test_changed_original_source_rejected(self):
        changed = self.source.replace("w[-32:]", "w[-31:]")
        with self.assertRaises(ValueError):
            login.validate_source(changed)

    def test_undersized_modulus_rejected(self):
        with self.assertRaisesRegex(ValueError, "modulus"):
            login.recover_mac_hash(1237, 13, b"test", lambda m, c: True)

    def test_local_original_token_forgery(self):
        digest, token = login.local_demo(self.source)
        self.assertEqual(len(digest), 32)
        msg, sep, encrypted_mac = token.partition(b"|")
        self.assertEqual(sep, b"|")
        self.assertTrue(msg.startswith(b"user=user"))
        self.assertTrue(msg.endswith(b"user=admin"))
        self.assertGreater(int.from_bytes(encrypted_mac, "big"), 0)

class HoroscopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = DATA / "horoscopes"

    def test_original_gemini_capsule_flag(self):
        self.assertEqual(horoscopes.solve(self.root), ["DUCTF{g3mini_pr0t0col_s4ved_us}"])

    def test_gemini_request_format(self):
        self.assertEqual(
            horoscopes.gemini_request("gemini://example.org/salvaging.gmi"),
            b"gemini://example.org/salvaging.gmi\r\n",
        )

    def test_invalid_request_scheme(self):
        with self.assertRaises(ValueError):
            horoscopes.gemini_request("https://example.org/")

    def test_parse_successful_gemini_response(self):
        status, meta, body = horoscopes.parse_response(b"20 text/gemini\r\n# Hello\n")
        self.assertEqual((status, meta, body), (20, "text/gemini", "# Hello\n"))

    def test_missing_header_rejected(self):
        with self.assertRaises(ValueError):
            horoscopes.parse_response(b"# Hello without header")

    def test_relative_links(self):
        page = "=> /salvaging.gmi Salvage\n=> gemini://example.org/another.gmi next\n"
        result = horoscopes.links(page, "gemini://example.org/index.gmi")
        self.assertEqual(result, [
            "gemini://example.org/salvaging.gmi",
            "gemini://example.org/another.gmi",
        ])

    def test_directory_traversal_rejected(self):
        respond = horoscopes.local_capsule(self.root)
        self.assertEqual(
            respond("gemini://local-ctf.invalid/../secrets.txt"),
            b"51 NOT FOUND\r\n"
        )

    def test_external_links_ignored(self):
        def respond(url):
            if url.endswith("index.gmi") or url.endswith("/"):
                return b"20 text/gemini\r\n=> gemini://evil.invalid/flag.gmi outside"
            raise AssertionError(f"unexpected network navigation: {url}")
        self.assertEqual(horoscopes.crawl("gemini://good.invalid/", respond), [])

    def test_non_success_ignored(self):
        self.assertEqual(
            horoscopes.crawl(
                "gemini://good.invalid/",
                lambda url: b"51 NOT FOUND\r\nDUCTF{not_a_real_flag}",
            ),
            [],
        )

if __name__ == "__main__":
    unittest.main()
