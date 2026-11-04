"""Phase 21 independent tests: fake CPython pointer layout and GMP/MITM.

Previous 20 Python unittest modules remain untouched. These tests never
mutate real CPython objects, call libc.system, or connect to a challenge.
Original author's exploit source is read strictly as text.
"""
import dataclasses
import math
import unittest
from pathlib import Path

from solvers import fakeobj, cheap_logs

ROOT = Path(__file__).resolve().parents[1] / "data"


class FakeObjTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (ROOT / "fakeobj/original_fakeobj.py").read_text(encoding="utf-8")
        cls.author = (ROOT / "fakeobj/original_solver.py").read_text(encoding="utf-8")

    def test_original_source_contract(self):
        fakeobj.validate_source(self.original, self.author)

    def test_reproduce_original_72_byte_layout(self):
        layout = fakeobj.build_layout()
        self.assertEqual(len(layout.overwritten_bytes), 72)
        self.assertTrue(fakeobj.verify_layout(layout))
        self.assertEqual(fakeobj.unpack_pointer(layout.overwritten_bytes, 8),
                         layout.object_address - 88 + 16)

    def test_fake_tp_repr_resolves_to_test_function(self):
        layout = fakeobj.build_layout()
        self.assertEqual(layout.repr_field_address, layout.object_address + 16)
        self.assertEqual(fakeobj.unpack_pointer(layout.overwritten_bytes, 16),
                         fakeobj.SIMULATED_FUNCTION)

    def test_simulated_refcount_byte_increment_only(self):
        layout = fakeobj.build_layout()
        self.assertEqual(layout.simulated_argument, b"/local\x00\x00")
        self.assertNotIn(b"/bin/sh", layout.overwritten_bytes)

    def test_memory_writes_do_not_touch_guard_region(self):
        layout = fakeobj.build_layout()
        memory = fakeobj.simulate_original_overwrite(layout.overwritten_bytes)
        self.assertEqual(memory[:72], layout.overwritten_bytes)
        self.assertEqual(memory[72:], b"\xCC" * 24)

    def test_original_layout_source_verifies(self):
        layout = fakeobj.solve_local(self.original, self.author)
        self.assertTrue(fakeobj.verify_layout(layout))

    def test_invalid_callback_marker_rejected(self):
        for marker in (b"/bin/sh\x00", b"short", b".unclosed"):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                fakeobj.build_layout(marker=marker)

    def test_pointer_range_and_alignment_checks(self):
        with self.assertRaises(ValueError):
            fakeobj.build_layout(object_address=0x7011)
        with self.assertRaises(ValueError):
            fakeobj.pack_pointer(2**64)

    def test_missing_pointer_data_rejected(self):
        with self.assertRaises(ValueError):
            fakeobj.unpack_pointer(b"short", 0)
        with self.assertRaises(ValueError):
            fakeobj.simulate_original_overwrite(b"short")

    def test_corrupted_payload_detected(self):
        layout = fakeobj.build_layout()
        wrong = dataclasses.replace(layout, overwritten_bytes=b"\x00" * 72)
        with self.assertRaises(ValueError):
            fakeobj.verify_layout(wrong)

    def test_changed_original_source_detected(self):
        with self.assertRaises(ValueError):
            fakeobj.validate_source(self.original.replace("range(72)", "range(64)"),
                                    self.author)


class CheapLogsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (ROOT / "cheap_logs/original_chall.c").read_text(encoding="utf-8")
        cls.author = (ROOT / "cheap_logs/original_solver.py").read_text(encoding="utf-8")
        cls.model = cheap_logs.Model(
            prime=2305843009213693951, generator=37, constant=1234567,
            aslr_coefficient=104729, byte_coefficient=65537,
            low_bits=5, high_bits=6, byte_bits=4)

    def test_original_gmp_source_and_author_mitm_contract(self):
        cheap_logs.validate_original_source(self.original, self.author)

    def test_parse_original_public_modulus(self):
        prime = cheap_logs.original_modulus(self.original)
        self.assertGreater(prime.bit_length(), 900)
        self.assertIn("mpz_set_str", self.original)

    def test_bounded_discrete_log_recovers_three_unknowns(self):
        secret = (21, 37, 11)
        public = cheap_logs.observed_public(self.model, *secret)
        self.assertEqual(cheap_logs.recover_bounded(self.model, public), secret)

    def test_varied_bounded_inputs(self):
        for secret in ((0, 0, 0), (31, 63, 15), (3, 17, 9), (17, 3, 0)):
            with self.subTest(secret=secret):
                public = cheap_logs.observed_public(self.model, *secret)
                self.assertEqual(cheap_logs.recover_bounded(self.model, public), secret)

    def test_exponent_affine_equation(self):
        low, high, byte = 7, 12, 5
        want = (self.model.constant
                + self.model.aslr_coefficient * (7 + (12 << 5))
                + self.model.byte_coefficient * 5)
        self.assertEqual(cheap_logs.exponent(self.model, low, high, byte), want)

    def test_invalid_variable_outside_bound(self):
        with self.assertRaises(ValueError):
            cheap_logs.observed_public(self.model, 32, 0, 0)
        with self.assertRaises(ValueError):
            cheap_logs.observed_public(self.model, 0, 64, 0)

    def test_ambiguous_field_rejected(self):
        degenerate = cheap_logs.Model(7, 2, 0, 3, 3, 2, 2, 2)
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            cheap_logs.recover_bounded(degenerate, 1)

    def test_invalid_public_rejected(self):
        with self.assertRaises(ValueError):
            cheap_logs.recover_bounded(self.model, 0)

    def test_unbounded_search_rejected(self):
        huge = dataclasses.replace(self.model, low_bits=13)
        with self.assertRaises(ValueError):
            cheap_logs.recover_bounded(huge, 1)

    def test_wrong_original_contract_rejected(self):
        with self.assertRaises(ValueError):
            cheap_logs.validate_original_source(
                self.original.replace("free(buf);", "/* no free */"), self.author)

    def test_local_original_constants_and_synthetic_recovery(self):
        result = cheap_logs.local_demo(self.original, self.author)
        self.assertEqual(result["synthetic_unknowns"], (21, 37, 11))
        self.assertFalse(result["original_heap_exploited"])
        self.assertFalse(result["hosted_flag_recovered"])

    def test_no_expected_flag_in_solver_outputs(self):
        result = cheap_logs.local_demo(self.original, self.author)
        self.assertNotIn("flag", str(result.get("synthetic_unknowns", "")))


if __name__ == "__main__":
    unittest.main()
