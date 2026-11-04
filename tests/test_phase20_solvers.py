"""Phase 20 regressions for distinct SH-RSA and BLAST challenges.

Previous 19 unittest files remain unchanged. Tests use actual source
contracts, a synthetic RSA key and deterministic 16x16 Fortran-style
uint8 matrices. They do not claim hosted CTF Flag retrieval.
"""
import hashlib
import math
import unittest
from pathlib import Path

from solvers import sh_rsa, blast

DATA = Path(__file__).resolve().parents[1] / "data"


class ShortHashRSATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "sh_rsa/original_challenge.py").read_text(encoding="utf-8")
        cls.original_solve = (DATA / "sh_rsa/original_solver.py").read_text(encoding="utf-8")

    def test_original_source_contract(self):
        sh_rsa.validate_source(self.source)
        self.assertIn("ls = 23", self.original_solve)

    def test_shake_digest_matches_original_hash_formula(self):
        n, message = 1234567891011121314, b"example"
        self.assertEqual(sh_rsa.H(n, message),
                         hashlib.shake_128(sh_rsa.int_bytes(n) + message).digest(8))
        self.assertEqual(len(sh_rsa.H(n, message)), 8)

    def test_signatures_verify_using_original_prefix_rule(self):
        p, q, e = 32416190071, 32416187567, 65537
        n = p * q
        d = pow(e, -1, (p-1)*(q-1))
        for message in (b"", b"challenge", b"offline-synthetic"):
            with self.subTest(message=message):
                sig = sh_rsa.sign(n, d, message)
                self.assertTrue(sh_rsa.verify(n, e, message, sig))
                self.assertEqual(pow(sig, e, n),
                                 int.from_bytes(sh_rsa.H(n, message), "big"))

    def test_product_of_signed_hashes_is_modular_product(self):
        p, q, e = 32416190071, 32416187567, 65537
        n = p*q
        d = pow(e, -1, (p-1)*(q-1))
        messages = [b"a", b"b", b"c"]
        signed = [sh_rsa.sign(n, d, m) for m in messages]
        combined = sh_rsa.multiply_signed_subset(n, signed, [0, 2])
        self.assertEqual(pow(combined, e, n),
                         (int.from_bytes(sh_rsa.H(n, b"a"), "big") *
                          int.from_bytes(sh_rsa.H(n, b"c"), "big")) % n)

    def test_exact_meet_in_middle_recovers_synthetic_subset(self):
        factors = [3, 5, 7, 11, 13, 17, 19, 23]
        result = sh_rsa.subset_product_exact(factors, 5*11*19)
        self.assertIsNotNone(result)
        self.assertEqual(math.prod(factors[i] for i in result), 5*11*19)

    def test_reject_nonexistent_subset(self):
        self.assertIsNone(sh_rsa.subset_product_exact([2, 3, 5, 7], 11))

    def test_reject_large_subset_demo(self):
        with self.assertRaises(ValueError):
            sh_rsa.subset_product_exact([2]*21, 4)

    def test_reject_invalid_signature(self):
        with self.assertRaises(ValueError):
            sh_rsa.recovered_prefix(100, 65537, 100)

    def test_local_original_contract_and_toy_crypto(self):
        result = sh_rsa.local_demo(self.source)
        self.assertTrue(result["synthetic_signature_valid"])
        self.assertFalse(result["full_challenge_forged"])

    def test_original_source_change_detected(self):
        with self.assertRaises(ValueError):
            sh_rsa.validate_source(self.source.replace("digest(8)", "digest(16)"))


class BlastTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "blast/original_main.f90").read_text(encoding="utf-8")
        cls.original_solver = (DATA / "blast/original_solver.py").read_text(encoding="utf-8")

    def test_original_fortran_contract(self):
        blast.validate_source(self.source)
        self.assertIn("B.inverse() * A", self.original_solver)

    def test_original_uint8_wraparound(self):
        self.assertEqual(blast.matrix_multiply([[250, 50]], [[2], [2]]),
                         [[88]])

    def test_fortran_column_major_order(self):
        self.assertEqual(blast.column_major_wire([[1, 2], [3, 4], [5, 6]]),
                         [1, 3, 5, 2, 4, 6])

    def test_nontrivial_odd_pivot_inverse(self):
        matrix = [[2, 1], [1, 1]]
        inverse = blast.invert_mod256(matrix)
        self.assertEqual(blast.matrix_multiply(matrix, inverse), [[1, 0], [0, 1]])
        self.assertEqual(blast.matrix_multiply(inverse, matrix), [[1, 0], [0, 1]])

    def test_even_pivot_singular_mod_256(self):
        with self.assertRaises(ValueError):
            blast.invert_mod256([[2, 0], [0, 1]])

    def test_synthetic_16x16_original_dimension(self):
        result = blast.local_demo(self.source)
        self.assertEqual(result["dimension"], 16)
        self.assertEqual(result["recovered_synthetic_vector"], list(range(16)))
        self.assertFalse(result["original_binary_exploited"])

    def test_recover_known_vector(self):
        matrix = [[3, 2, 7], [0, 5, 3], [0, 0, 9]]
        vector = [121, 244, 8]
        output = blast.apply_transform(matrix, vector)
        self.assertEqual(blast.recover_input(matrix, output), vector)

    def test_input_dimensions_checked(self):
        with self.assertRaises(ValueError):
            blast.matrix_multiply([[1, 2]], [[1, 2]])
        with self.assertRaises(ValueError):
            blast.recover_input([[1, 0], [0, 1]], [1])

    def test_source_change_rejected(self):
        with self.assertRaises(ValueError):
            blast.validate_source(self.source.replace("UNSIGNED(KIND=UINT8)", "INTEGER(KIND=8)"))

    def test_ragged_matrix_rejected(self):
        with self.assertRaises(ValueError):
            blast.invert_mod256([[1, 0], [1]])


if __name__ == "__main__":
    unittest.main()
