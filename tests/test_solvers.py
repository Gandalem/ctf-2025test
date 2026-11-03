"""Regression tests against original DUCTF 2025 challenge inputs."""
import unittest
from pathlib import Path
from solvers import dtmf, caterpillar

DATA = Path(__file__).resolve().parents[1] / "data"

class DTMFTests(unittest.TestCase):
    def test_official_input(self):
        raw = (DATA / "dtmf.txt").read_text(encoding="utf-8")
        self.assertEqual(dtmf.solve(raw), "DUCTF{onlyninetieskidswillrememberthis}")

    def test_known_sum_and_multitap(self):
        self.assertEqual(dtmf.decode_dtmf("203320332418"), "22#")
        self.assertEqual(dtmf.decode_multitap("22#"), "b")

    def test_invalid_sum(self):
        with self.assertRaises(ValueError):
            dtmf.solve("0000")

    def test_truncated_signal(self):
        with self.assertRaises(ValueError):
            dtmf.solve("224")

class CaterpillarTests(unittest.TestCase):
    def test_official_input(self):
        raw = (DATA / "caterpillar_output.txt").read_text(encoding="utf-8")
        self.assertEqual(
            caterpillar.recover(raw),
            "DUCTF{the_hungry_little_p_smooth_caterpillar_wow_an_allegory_for_life}"
        )

    def test_missing_cribs_not_mistaken_for_solved(self):
        raw = (DATA / "caterpillar_output.txt").read_text(encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Underdetermined"):
            caterpillar.recover(raw, {0: "D", 1: "U"})

    def test_inconsistent_cribs(self):
        raw = (DATA / "caterpillar_output.txt").read_text(encoding="utf-8")
        bad = dict(caterpillar.DEFAULT_CRIBS)
        bad[2] = "Z"
        with self.assertRaisesRegex(ValueError, "Inconsistent"):
            caterpillar.recover(raw, bad)

    def test_reject_malformed_challenge(self):
        with self.assertRaises(ValueError):
            caterpillar.recover("0123456789abcdef")

if __name__ == "__main__":
    unittest.main()
