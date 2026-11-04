"""New phase-6 test module; existing tests and original fixture layouts reused."""
import shutil
import unittest
from pathlib import Path
from solvers import clickme, philtered

DATA = Path(__file__).resolve().parents[1] / "data"

class ClickMeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "clickme_app.swift").read_text(encoding="utf-8")

    def test_real_original_source_flag(self):
        self.assertEqual(
            clickme.solve(self.source),
            "DUCTF{just_because_the_button_is_greyed_out_doesnt_mean_you_cant_use_it}",
        )

    def test_array_extracted_from_disabled_button(self):
        self.assertEqual(len(clickme.parse_encoded_flag(self.source)), 72)

    def test_missing_button_rejected(self):
        with self.assertRaisesRegex(ValueError, "Flag button"):
            clickme.solve("let a: [UInt8] = [0]")

    def test_corrupt_formula_rejected(self):
        with self.assertRaisesRegex(ValueError, "formula"):
            clickme.solve(self.source.replace("38 * i + 17", "9 * i + 4"))

    def test_invalid_cipher_byte_rejected(self):
        corrupted = self.source.replace("[85, 98, 30", "[655, 98, 30", 1)
        with self.assertRaisesRegex(ValueError, "Invalid encoded bytes"):
            clickme.solve(corrupted)

@unittest.skipUnless(shutil.which("php"), "PHP CLI unavailable")
class PhilteredTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge_root = DATA / "philtered"

    def test_offline_fixture_leaks_synthetic_secret(self):
        self.assertEqual(
            philtered.solve(self.challenge_root, "DUCTF{UNIQUE_SYNTHETIC_SECRET}"),
            "DUCTF{UNIQUE_SYNTHETIC_SECRET}",
        )

    def test_payload_order_and_wrapper(self):
        payload = philtered.create_payload()
        self.assertLess(payload.index("allow_unsafe"), payload.index("config%5B"))
        self.assertIn("php%3A%2F%2Ffilter", payload)
        self.assertIn("flag.php", payload)

    def test_blacklist_blocks_without_override(self):
        query = ("config%5Bdata_folder%5D="
                 "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D"
                 "&config%5Bpath%5D=flag.php")
        response = philtered.run_fixture(
            self.challenge_root, "DUCTF{SAFE_MARKER}", query
        )
        with self.assertRaisesRegex(ValueError, "No leaked"):
            philtered.extract_flag_from_response(response)

    def test_empty_resource_rejected(self):
        with self.assertRaises(ValueError):
            philtered.create_payload("")

    def test_missing_fixtures_rejected(self):
        with self.assertRaises(ValueError):
            philtered.run_fixture(DATA / "does_not_exist", "DUCTF{MARKER}")

    def test_bad_marker_rejected(self):
        with self.assertRaises(ValueError):
            philtered.run_fixture(self.challenge_root, "dangerous-code")

if __name__ == "__main__":
    unittest.main()
