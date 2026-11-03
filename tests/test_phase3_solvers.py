"""Phase 3: separate regression suite using real public CTF input fixtures."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from solvers import mini_me, vimfu

DATA = Path(__file__).resolve().parents[1] / "data"

class MiniMeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "mini_me_sourcemap.json").read_text(encoding="utf-8")

    def test_actual_leaked_key(self):
        # Published challenge .env establishes the expected secret key.
        self.assertEqual(
            mini_me.extract_key(self.source), "TUNG-TUNG-TUNG-TUNG-SAHUR"
        )

    def test_invalid_map(self):
        with self.assertRaises(ValueError):
            mini_me.extract_key(json.dumps({"sourcesContent": []}))

    def test_truncated_obfuscation(self):
        payload = json.loads(self.source)
        payload["sourcesContent"][0] = payload["sourcesContent"][0].replace(
            '["85"]', '["bad"]', 1
        )
        with self.assertRaises(ValueError):
            mini_me.extract_key(json.dumps(payload))

    def test_missing_source_map(self):
        with self.assertRaises(ValueError):
            mini_me.extract_key('{"version":3}')

@unittest.skipUnless(shutil.which("vim"), "Vim executable unavailable")
class VimfuTests(unittest.TestCase):
    def test_real_macro_and_original_lock(self):
        self.assertEqual(
            vimfu.solve(DATA / "vimfu_key.txt", DATA / "vimfu_lock.txt"),
            "DUCTF{3Welc0me_.Tru3-VI-cult1s7!}",
        )

    def test_missing_inputs_rejected(self):
        with self.assertRaises(ValueError):
            vimfu.solve(DATA / "not-found-key", DATA / "vimfu_lock.txt")

    def test_invalid_macro_cannot_fake_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "bad-macro"
            key.write_text("gg0", encoding="ascii")
            with self.assertRaises((RuntimeError, ValueError)):
                vimfu.solve(key, DATA / "vimfu_lock.txt")

if __name__ == "__main__":
    unittest.main()
