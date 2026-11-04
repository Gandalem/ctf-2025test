"""Phase 17: independent S3 User-Agent and Legendary PHP source tests.

All previous 16 Python regression modules and their inputs are kept
unchanged. Neither module contacts the published S3 URL or a PHP server.
"""
import datetime as dt
import json
import shutil
import unittest
from pathlib import Path

from solvers import kick_the_bucket as s3, legendary

ROOT = Path(__file__).resolve().parents[1]
S3 = ROOT / "data/kick_the_bucket"
WEB = ROOT / "data/legendary"


class KickTheBucketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_policy = (S3 / "s3_resource_policy.json").read_text(encoding="utf-8")
        cls.original_url = (S3 / "s3_presigned_url.txt").read_text(encoding="utf-8")
        cls.policy = s3.load_policy(cls.original_policy)

    def test_original_user_agent_resource_condition(self):
        self.assertEqual(s3.user_agent_condition(self.policy), "aws-sdk-go*")

    def test_spoofed_agent_matches_original_condition(self):
        for value in ("aws-sdk-go", "aws-sdk-go-ctf-local-test",
                      "aws-sdk-go/1.0", "aws-sdk-go-malformed"):
            self.assertTrue(s3.offline_authorized_user_agent(self.policy, value))
        for value in ("curl/8.0", "Mozilla/5.0", "", "AWS-SDK-GO"):
            self.assertFalse(s3.offline_authorized_user_agent(self.policy, value))

    def test_presigned_url_has_unsigned_user_agent(self):
        details = s3.parse_presigned_url(self.original_url)
        self.assertEqual(details["signed_headers"], ["host"])
        self.assertEqual(details["path"], "/flag.txt")
        self.assertNotIn("user-agent", details["signed_headers"])

    def test_expired_historical_presigned_url(self):
        details = s3.parse_presigned_url(self.original_url)
        expected = dt.datetime(2025, 7, 22, 12, 47, 55, tzinfo=s3.UTC)
        self.assertEqual(details["expires"], expected)
        result = s3.analyse(
            self.original_policy, self.original_url,
            dt.datetime(2026, 11, 4, tzinfo=s3.UTC),
        )
        self.assertTrue(result["expired"])
        self.assertFalse(result["user_agent_is_signed"])

    def test_valid_then_expired_time_window(self):
        details = s3.parse_presigned_url(self.original_url)
        before = s3.analyse(self.original_policy, self.original_url,
                            details["issued"] + dt.timedelta(seconds=10))
        after = s3.analyse(self.original_policy, self.original_url,
                           details["expires"])
        self.assertFalse(before["expired"])
        self.assertTrue(after["expired"])

    def test_invalid_aws_policy_rejected(self):
        with self.assertRaises(ValueError):
            s3.load_policy('{"Version":"2008-10-17","Statement":[]}')

    def test_invalid_signature_expiry_rejected(self):
        with self.assertRaises(ValueError):
            s3.parse_presigned_url(self.original_url.replace("604800", "604801"))

    def test_original_policy_unchanged_provides_no_s3_operation(self):
        parsed = json.loads(self.original_policy)
        self.assertEqual(parsed["Statement"][0]["Action"], "s3:GetObject")
        self.assertEqual(parsed["Statement"][0]["Effect"], "Allow")


@unittest.skipUnless(shutil.which("php"), "PHP CLI needed to test original PHP helpers")
class LegendaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = (WEB / "api.php").read_text(encoding="utf-8")
        cls.index = (WEB / "index.php").read_text(encoding="utf-8")
        cls.nginx = (WEB / "nginx.conf").read_text(encoding="utf-8")
        cls.original_shell = (WEB / "original_solve.sh").read_text(encoding="utf-8")

    def test_original_php_nginx_contract(self):
        legendary.validate_sources(self.api, self.index, self.nginx)

    def test_original_shell_payload_double_decodes(self):
        raw = legendary.parse_original_payload(self.original_shell)
        decoded = legendary.decode_twice(raw)
        self.assertIn("imagedir from (select", decoded)
        self.assertIn("0x676c6f623a2f2f2f662a", decoded)
        self.assertNotEqual(raw, decoded)

    def test_original_php_hmac_matches_python(self):
        route = "/api/animal/quokka"
        php = legendary.php_local_probe(self.api, route, "imagedir")
        self.assertEqual(php["signature"], legendary.hmac_signature(route))
        self.assertEqual(php["escaped"], "\x60imagedir\x60")

    def test_original_php_identifier_escaping_matches_python(self):
        for value in ("safe", "name,size", "a\x60b", "\x60\x60"):
            with self.subTest(value=value):
                php = legendary.php_local_probe(self.api, "route", value)
                self.assertEqual(php["escaped"], legendary.escaped_identifier(value))

    def test_original_payload_analysis(self):
        result = legendary.analyse(
            self.original_shell, self.api, self.index, self.nginx)
        self.assertEqual(len(result["signature"]), 64)
        self.assertTrue(result["decoded_route"].startswith("/api/animal/"))
        self.assertIn(" FROM animals WHERE name = ?", result["sql_field_shape"])

    def test_original_solve_script_not_executed(self):
        # This test deliberately treats the public shell exploit as DATA;
        # neither a network request nor SQL statement is actually executed.
        payload = legendary.parse_original_payload(self.original_shell)
        self.assertTrue(payload.startswith("/api/animal/"))
        self.assertNotIn("localhost:1337", payload)

    def test_missing_helpers_rejected(self):
        with self.assertRaises(ValueError):
            legendary.extract_php_function("<?php echo 1;", "api_sig_gen")
        with self.assertRaises(ValueError):
            legendary.extract_php_function(self.api, "shell_exec")

    def test_changed_source_rejected(self):
        with self.assertRaises(ValueError):
            legendary.validate_sources(
                self.api.replace("hash_hmac('sha256'", "hash_hmac('sha1'"),
                self.index, self.nginx)

    def test_hmac_does_not_accept_different_route(self):
        p = legendary.hmac_signature("/api/animal/quokka")
        q = legendary.hmac_signature("/api/animal/emu")
        self.assertNotEqual(p, q)


if __name__ == "__main__":
    unittest.main()
