"""Phase 15 independent regressions for GGSP and File Upload challenges.

Keeps all existing 14 Python test modules and original data fixtures intact.
"""
import math
import shutil
import unittest
from pathlib import Path
from Crypto.PublicKey import ECC
from Crypto.Util.number import getPrime

from solvers import good_game_spawn_point as ggsp, file_upload

DATA = Path(__file__).resolve().parents[1] / "data"


class GGSPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_file = DATA / "good_game_spawn_point/chal.py"
        cls.source = cls.source_file.read_text(encoding="utf-8")

    def test_original_challenge_contract(self):
        ggsp.validate_source(self.source)

    def test_paillier_encrypt_decrypt(self):
        p, q = getPrime(128), getPrime(128)
        n = p * q
        for number in (0, 1, 2, 65535, n - 1):
            self.assertEqual(
                ggsp.paillier_decrypt(ggsp.paillier_encrypt(number, n), p, q),
                number,
            )

    def test_bsgs_on_real_p256_points(self):
        for value in (0, 1, 2, 42, 177):
            self.assertEqual(
                ggsp.bounded_log(ggsp.GENERATOR * value, 256), value
            )

    def test_bsgs_beyond_bound(self):
        self.assertIsNone(ggsp.bounded_log(ggsp.GENERATOR * 999, 256))

    def test_reject_too_large_log(self):
        with self.assertRaises(ValueError):
            ggsp.bounded_log(ggsp.GENERATOR * 3, 10_000_001)

    def test_reject_invalid_paillier_message(self):
        n = 123
        with self.assertRaises(ValueError):
            ggsp.paillier_encrypt(n, n)

    def test_recover_small_secret_via_original_mta_and_schnorr(self):
        self.assertEqual(ggsp.original_local_demo(self.source_file, 12345), 12345)

    def test_a_different_original_secret(self):
        self.assertEqual(ggsp.original_local_demo(self.source_file, 27182), 27182)

    def test_no_out_of_scope_secret(self):
        with self.assertRaisesRegex(ValueError, "16-bit"):
            ggsp.original_local_demo(self.source_file, 1 << 200)

    def test_empty_observations_rejected(self):
        with self.assertRaises(ValueError):
            ggsp.recover_small_secret([], ggsp.GENERATOR)


@unittest.skipUnless(shutil.which("file"), "Unix file MIME sniffer required")
class FileUploadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = DATA / "file_upload"
        cls.source = (cls.root / "appupload.py").read_text(encoding="utf-8")
        cls.viewer = (cls.root / "appview.py").read_text(encoding="utf-8")

    def test_original_flask_source_contract(self):
        file_upload.validate_source(self.source, self.viewer)

    def test_original_flask_upload_and_redirect(self):
        name, redirect, mime = file_upload.original_upload_demo(
            self.root / "appupload.py", self.root / "appview.py",
            self.root / "templates",
        )
        self.assertTrue(redirect.endswith("/" + name))
        self.assertTrue(name.startswith(
            "44866e4affbce53ef20a5a3387fd58ed594724ff8c3bf5bda17a39cbbcd03919-"
        ) or len(name.split("-")[0]) == 64)
        self.assertIn("text/html", mime)

    def test_benign_html_has_local_marker(self):
        html = file_upload.benign_html()
        self.assertIn(b"DUCTF_LOCAL_UPLOAD_PROOF", html)
        self.assertNotIn(b"https://", html)
        self.assertNotIn(b"document.cookie", html)
        self.assertNotIn(b"serviceWorker", html)

    def test_reject_unsafe_marker(self):
        for marker in ("x", "test<script>", "https://evil.invalid", "ABC\nDEF"):
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError):
                    file_upload.benign_html(marker)

    def test_missing_original_viewer_check(self):
        with self.assertRaises(ValueError):
            file_upload.validate_source(self.source, "print('no MIME')")

    def test_missing_template_folder(self):
        with self.assertRaises(ValueError):
            file_upload.load_original(
                self.root / "appupload.py", self.root / "missing-templates",
            )


if __name__ == "__main__":
    unittest.main()
