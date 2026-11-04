"""Phase 7: independent CrackMe and ECB regression suite.

All original phase 1-6 tests are discovered unchanged. The real Swift
source and the real ECB backend implementation are kept under data/.
"""
import unittest
from pathlib import Path

from solvers import crackme, ecb_a_tron

DATA = Path(__file__).resolve().parents[1] / "data"


class CrackMeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "crackme.swift").read_text(encoding="utf-8")

    def test_original_flag_from_constraints(self):
        self.assertEqual(
            crackme.solve(self.source),
            "DUCTF{cho05iNg_A_p4s5W0rd_15_h4Rd...}",
        )

    def test_password_has_valid_swift_hashes(self):
        password = crackme.recover_password(self.source)
        self.assertEqual(len(password), 29)
        self.assertEqual(crackme.hash_swift(password) & 0xffffffff, 3633363637)
        self.assertEqual(crackme.hash_swift(password[::-1]) >> 32, 2161988486)

    def test_source_comment_not_used_as_answer(self):
        cleaned = "\n".join(
            line for line in self.source.splitlines()
            if not line.lstrip().startswith("//")
        )
        self.assertEqual(crackme.solve(cleaned), crackme.solve(self.source))

    def test_linear_algebra_from_original_source(self):
        expected = crackme.solve_three(
            crackme.linear_constraints(self.source, ("v2", "v6", "v8"))
        )
        self.assertEqual(expected, "oN_")

    def test_modified_hash_rejected(self):
        altered = self.source.replace("3633363637", "3633363638")
        with self.assertRaisesRegex(ValueError, "hash check failed"):
            crackme.solve(altered)

    def test_inconsistent_positional_constraint(self):
        altered = self.source.replace('every3rdFrom1 == "5g"', 'every3rdFrom1 == "4g"')
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            crackme.solve(altered)

    def test_missing_equation_rejected(self):
        altered = self.source.replace(
            "1*v2 + 2*v6 + 3*v8 == 552", "unrecognized equation"
        )
        with self.assertRaises(ValueError):
            crackme.solve(altered)


class ECBTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "ecb_a_tron_main.py").read_text(encoding="utf-8")

    def oracle(self, secret: bytes, key: bytes = bytes(range(16))):
        return ecb_a_tron.local_oracle(secret, key)

    def test_challenge_source_matches_attack_assumptions(self):
        ecb_a_tron.validate_source(self.source)

    def test_recover_local_synthetic_flag(self):
        secret = b"DUCTF{LOCAL_SYNTHETIC_ONLY}"
        oracle, batch = self.oracle(secret)
        self.assertEqual(ecb_a_tron.recover_secret(oracle, batch), secret)

    def test_recover_secret_exact_block_boundary(self):
        secret = b"ABCDEFGHIJKLMNOP"
        oracle, batch = self.oracle(secret)
        self.assertEqual(ecb_a_tron.recover_secret(oracle, batch), secret)

    def test_recover_secret_spanning_blocks(self):
        secret = b"A" * 18 + b"\x00\xff XYZ"
        oracle, batch = self.oracle(secret, b"\xff" * 16)
        self.assertEqual(ecb_a_tron.recover_secret(oracle, batch), secret)

    def test_recover_trailing_space(self):
        secret = b"secret has trailing spaces  "
        oracle, batch = self.oracle(secret)
        self.assertEqual(ecb_a_tron.recover_secret(oracle, batch), secret)

    def test_recover_without_batch(self):
        secret = b"no batch"
        oracle, _ = self.oracle(secret)
        self.assertEqual(ecb_a_tron.recover_secret(oracle), secret)

    def test_reject_changed_protocol(self):
        with self.assertRaisesRegex(ValueError, "property missing"):
            ecb_a_tron.validate_source(self.source.replace("AES.MODE_ECB", "AES.MODE_CBC"))

    def test_reject_bad_key(self):
        with self.assertRaisesRegex(ValueError, "16 bytes"):
            ecb_a_tron.local_oracle(b"x", b"bad")

    def test_reject_unreasonable_search_bound(self):
        oracle, batch = self.oracle(b"x" * 20)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            ecb_a_tron.recover_secret(oracle, batch, max_length=10)

    def test_reject_incomplete_batch(self):
        oracle, batch = self.oracle(b"xyz")
        with self.assertRaisesRegex(ValueError, "number of results"):
            ecb_a_tron.recover_secret(oracle, lambda probes: batch(probes)[:1])

    def test_batch_limit(self):
        _, batch = self.oracle(b"sample")
        with self.assertRaisesRegex(ValueError, "256"):
            batch([b""] * 257)


if __name__ == "__main__":
    unittest.main()
