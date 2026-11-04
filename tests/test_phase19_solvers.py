"""Phase 19 independent original Sodium + M.A.R.Y regression tests.

Previous 18 unittest modules and their fixtures are not modified. Only the
original public CTF sources and synthetic inputs are used, with zero network
calls. Sodium's original AST is exercised without importing the RPC server.
"""
import dataclasses
import unittest
from pathlib import Path

from solvers import sodium, mary_lambda as mary

ROOT = Path(__file__).resolve().parents[1] / "data"


class SodiumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "sodium"
        cls.rpc = (path / "rpc_server.py").read_text(encoding="utf-8")
        cls.customer = (path / "customer_routes.py").read_text(encoding="utf-8")
        cls.proxy = (path / "pound.cfg").read_text(encoding="utf-8")
        cls.docker = (path / "Dockerfile").read_text(encoding="utf-8")

    def test_original_four_source_contracts(self):
        sodium.validate_sources(self.customer, self.rpc, self.proxy, self.docker)

    def test_original_two_pass_stats_formats_synthetic_flag(self):
        normal, poisoned = sodium.reproduce_original_format(self.rpc)
        self.assertIn(sodium.MARKER, poisoned)
        self.assertNotIn(sodium.MARKER, normal)
        self.assertIn("Current Configuration", poisoned)

    def test_original_ast_unmodified_functions_used(self):
        ns = sodium.extract_rpc_builders(self.rpc)
        self.assertEqual(ns["Config"].__name__, "Config")
        self.assertEqual(ns["config"].auth_key, "SYNTHETIC_AUTH_KEY")
        self.assertEqual(ns["config"].authorized_ips, ["127.0.0.1"])

    def test_no_logs_safe_when_get_config_false(self):
        ns = sodium.extract_rpc_builders(self.rpc)
        page = ns["build_stats_page"](get_log=False, get_config=False)
        self.assertNotIn(sodium.MARKER, page)
        self.assertIn("service health ok", page)

    def test_log_payload_requires_second_format_call(self):
        ns = sodium.extract_rpc_builders(self.rpc)
        intermediate = "synthetic audit entry: {config.__init__.__globals__[FLAG]}"
        self.assertNotIn(sodium.MARKER, intermediate)
        page = ns["build_stats_page"](get_log=True, get_config=True)
        self.assertIn(sodium.MARKER, page)

    def test_url_scheme_is_audit_only(self):
        result = sodium.url_scheme_audit(self.customer)
        self.assertEqual(result["candidate"], " file:///tmp/synthetic")
        self.assertIn(result["current_parser_scheme"], ("file", ""))
        self.assertIsInstance(result["blocked_by_blacklist"], bool)

    def test_no_actual_external_request_behavior(self):
        normal, poison = sodium.reproduce_original_format(self.rpc)
        self.assertNotIn("http://", normal)
        self.assertNotIn("http://", poison)

    def test_original_source_change_detected(self):
        with self.assertRaises(ValueError):
            sodium.validate_sources(
                self.customer,
                self.rpc.replace("return template.format(config=config)",
                                 "return template"),
                self.proxy, self.docker,
            )

    def test_original_ast_missing_class_detected(self):
        with self.assertRaises(ValueError):
            sodium.extract_rpc_builders("def build_stats_page(): return 1")

    def test_orig_config_uses_synthetic_not_host_secret(self):
        ns = sodium.extract_rpc_builders(self.rpc)
        self.assertEqual(ns["FLAG"], sodium.MARKER)
        self.assertTrue(ns["FLAG"].startswith("DUCTF{SYNTHETIC_"))


class MaryLambdaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "mary_lambda/main.tf").read_text(encoding="utf-8")
        cls.vars = (ROOT / "mary_lambda/variables.tf").read_text(encoding="utf-8")
        cls.audit = mary.audit_terraform(cls.source)

    def test_original_terraform_role_trust_contract(self):
        self.assertTrue(self.audit.user_trusted_by_lambda_role)
        self.assertTrue(self.audit.ssm_is_tag_conditioned)
        self.assertTrue(self.audit.ssm_parameter_is_challenge_tagged)

    def test_user_can_discover_lambda_but_not_ssm(self):
        self.assertTrue(mary.synthetic_permission_check(
            self.audit, "devopsadmin", "lambda:GetFunction",
            {"Challenge": "local-mary"}))
        self.assertFalse(mary.synthetic_permission_check(
            self.audit, "devopsadmin", "ssm:GetParameter",
            {"Challenge": "local-mary"}))

    def test_assumed_role_can_read_matching_tag(self):
        self.assertTrue(mary.synthetic_permission_check(
            self.audit, "lambda-role", "ssm:GetParameter",
            {"Challenge": "local-mary"}))
        self.assertTrue(self.audit.assume_role_then_getparameter)

    def test_assumed_role_denied_wrong_tag(self):
        for tags in ({}, {"Challenge": "other"}, {"environment": "production"}):
            with self.subTest(tags=tags):
                self.assertFalse(mary.synthetic_permission_check(
                    self.audit, "lambda-role", "ssm:GetParameter", tags))

    def test_unknown_principal_denied(self):
        self.assertFalse(mary.synthetic_permission_check(
            self.audit, "nobody", "ssm:GetParameter", {"Challenge": "local-mary"}))

    def test_original_terraform_analysis(self):
        result = mary.analyse(self.source)
        self.assertFalse(result["direct_user_access"])
        self.assertTrue(result["lambda_role_trusts_user"])
        self.assertTrue(result["assumed_role_access_with_matching_tag"])
        self.assertTrue(result["synthetic_only"])

    def test_original_source_role_blocks_are_balanced(self):
        for name in ("lambda_role_policy", "lambda_assume_role_policy",
                     "devopsadmin_policy"):
            self.assertIn("statement", mary.balanced_block(self.source, "data", name))

    def test_original_flag_is_not_exposed_from_terraform(self):
        self.assertIn('value       = var.flag', self.source)
        self.assertIn('variable "flag"', self.vars)
        self.assertNotIn("DUCTF{", self.source)

    def test_no_role_trust_is_rejected(self):
        with self.assertRaises(ValueError):
            mary.audit_terraform(
                self.source.replace('"sts:AssumeRole"', '"sts:NotAllowed"'))

    def test_original_policy_tag_condition_enforced(self):
        with self.assertRaises(ValueError):
            mary.audit_terraform(self.source.replace(
                "aws:ResourceTag/Challenge", "aws:ResourceTag/Environment"))

    def test_missing_source_block_detected(self):
        with self.assertRaises(ValueError):
            mary.balanced_block(self.source, "data", "unrelated_role")


if __name__ == "__main__":
    unittest.main()
