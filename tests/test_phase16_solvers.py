"""Phase 16: independent original Express 4/5 Handlebars regression tests.

The previous fifteen unittest modules and all 30 preexisting solvers stay
unchanged. The Node adapter extracts actual published app.js heredocs from
the source Dockerfiles and binds loopback. Its only instrumentation is
replacing the fixed port listen call with module.exports.
"""
import json
import shutil
import subprocess
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode

from solvers import request_handling as ast, more_request_handling as gadget

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = {
    "ast": ROOT / "data" / "request_handling" / "Dockerfile",
    "gadget": ROOT / "data" / "more_request_handling" / "Dockerfile",
}
NODE_ADAPTER = ROOT / "tests" / "phase16_node_case.js"


def original_app_response(kind: str, query: str) -> tuple[int, str]:
    if kind not in DOCKERFILES:
        raise ValueError("Unknown challenge kind")
    run = subprocess.run(
        ["node", str(NODE_ADAPTER), str(DOCKERFILES[kind]), query],
        cwd=ROOT, capture_output=True, text=True, timeout=18, check=False,
    )
    if run.returncode:
        raise AssertionError(
            "Original Node challenge execution failed: " + run.stderr[-1800:])
    data = json.loads(run.stdout)
    return int(data["status"]), data["body"]


class RequestHandlingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = DOCKERFILES["ast"].read_text(encoding="utf-8")

    def test_original_express4_source_contract(self):
        ast.validate_source(self.source)

    def test_nested_query_contains_original_ast_nodes(self):
        data = ast.query_tree()
        self.assertEqual(data["x[type]"], "Program")
        self.assertEqual(data["x[body][0][type]"], "MustacheStatement")
        self.assertEqual(data["x[body][0][params][0][type]"], "NumberLiteral")
        self.assertNotIn("child_process", str(data))

    def test_query_parameter_encoding(self):
        parsed = parse_qs(ast.query_string())
        for key, value in ast.query_tree().items():
            self.assertEqual(parsed[key], [value])

    def test_reject_command_injection_as_marker(self):
        with self.assertRaises(ValueError):
            ast.query_tree("whoami;sh")
        with self.assertRaises(ValueError):
            ast.query_tree("DUCTF{INVALID}")

    def test_reject_different_express_version(self):
        with self.assertRaises(ValueError):
            ast.validate_source(self.source.replace("express@4", "express@5"))

    def test_positive_response_validation(self):
        self.assertTrue(ast.check_local_result(500, "Error: " + ast.MARKER))
        with self.assertRaises(ValueError):
            ast.check_local_result(200, "Error: " + ast.MARKER)

    def test_original_app_renders_plain_text(self):
        status, body = original_app_response("ast", urlencode({"x": "plain demo"}))
        self.assertEqual(status, 200)
        self.assertIn("plain demo", body)

    def test_original_express4_ast_marker_executes(self):
        status, body = original_app_response("ast", ast.query_string())
        self.assertEqual(status, 500, f"Unexpected Express 4 status/body: {status} {body[:1200]}")
        self.assertIn(ast.MARKER, body, f"Express 4 AST diagnostic: {body[:1800]}")


class MoreRequestHandlingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = DOCKERFILES["gadget"].read_text(encoding="utf-8")

    def test_original_express5_source_contract(self):
        gadget.validate_source(self.source)

    def test_template_uses_original_function_gadget(self):
        text = gadget.template()
        self.assertIn("req.socket.server._events.request.constructor.listenerCount", text)
        self.assertIn(gadget.MARKER, text)
        self.assertNotIn("child_process", text)

    def test_template_rejects_remote_or_code_markers(self):
        with self.assertRaises(ValueError):
            gadget.template("print('hello')")
        with self.assertRaises(ValueError):
            gadget.template("http://example.com/")

    def test_wrong_app_contract_rejected(self):
        with self.assertRaises(ValueError):
            gadget.validate_source(self.source.replace("express@5", "express@4"))

    def test_response_validation(self):
        self.assertTrue(gadget.check_local_result(500, "Error: " + gadget.MARKER))
        with self.assertRaises(ValueError):
            gadget.check_local_result(404, gadget.MARKER)

    def test_original_express5_plain_template(self):
        status, body = original_app_response("gadget", urlencode({"x": "normal template"}))
        self.assertEqual(status, 200)
        self.assertIn("normal template", body)

    def test_original_express5_function_marker_executes(self):
        status, body = original_app_response(
            "gadget", urlencode({"x": gadget.template()}))
        self.assertTrue(gadget.check_local_result(status, body))


if __name__ == "__main__":
    unittest.main()
