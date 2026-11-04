"""Sodium: reproduce the original RPC double-format bug offline.

This solver extracts unchanged Config and build_stats_page AST nodes from
the published challenge server, then executes ONLY those two nodes in a
synthetic namespace. The fake log contains DUCTF{SYNTHETIC_SODIUM_MARKER}.
It does not run the socket listener, logging or filesystem operations.

The challenge also involves URL scheme confusion and a h11/Pound parser
mismatch; those are identified by source checks, not a full proxy exploit.
No remote requests are made.
"""
import argparse
import ast
from pathlib import Path
from urllib.parse import urlsplit

MARKER = "DUCTF{SYNTHETIC_SODIUM_MARKER}"


def validate_sources(customer: str, rpc: str, proxy: str, docker: str) -> None:
    checks = (
        (customer, "scheme = urlparse(url).scheme"),
        (customer, "preview = urlopen(url).read()"),
        (rpc, "return template.format(config=config)"),
        (rpc, '""".format(logs=get_logs())'),
        (rpc, 'params[param.split("=")[0]] = bool(param.split("=")[1])'),
        (rpc, 'logger.error(f"[!] Error while fetching stats. Request made to: {target} with error: {e}")'),
        (proxy, 'Service "RPC Service"'),
        (proxy, 'Host "dev.rpc-service.ductf"'),
        (docker, "h11==0.15.0"),
        (docker, "pound-4.15"),
    )
    for text, fragment in checks:
        if fragment not in text:
            raise ValueError("Original Sodium source contract has changed")


def extract_rpc_builders(source: str) -> dict:
    """Load the two known public AST nodes, never the socket server module."""
    import datetime
    tree = ast.parse(source)
    wanted = [node for node in tree.body if (
        isinstance(node, ast.ClassDef) and node.name == "Config"
    ) or (
        isinstance(node, ast.FunctionDef) and node.name == "build_stats_page"
    )]
    if len(wanted) != 2:
        raise ValueError("Expected original Config class and stats builder")
    module = ast.Module(body=wanted, type_ignores=[])
    ast.fix_missing_locations(module)

    class FakeLogger:
        def error(self, _msg):
            return None

    class FakeEnv:
        @staticmethod
        def getenv(name, default=None):
            return {"FLAG": MARKER, "AUTHENTICATION_KEY": "SYNTHETIC_AUTH_KEY"}.get(name, default)

    namespace = {
        "datetime": datetime,
        "os": FakeEnv(),
        "logger": FakeLogger(),
        "FLAG": MARKER,
        "get_logs": lambda: "synthetic audit entry: {config.__init__.__globals__[FLAG]}",
    }
    exec(compile(module, "<original-public-sodium-rpc-builders>", "exec"), namespace)
    namespace["config"] = namespace["Config"]()
    return namespace


def reproduce_original_format(source: str) -> tuple[str, str]:
    namespace = extract_rpc_builders(source)
    normal = namespace["build_stats_page"](get_log=False, get_config=True)
    poisoned = namespace["build_stats_page"](get_log=True, get_config=True)
    if MARKER in normal or MARKER not in poisoned:
        raise ValueError("Original two-pass formatting was not demonstrated")
    return normal, poisoned


def url_scheme_audit(customer: str, candidate: str = " file:///tmp/synthetic") -> dict:
    """Never dereference candidate. Current Python may already fix the CVE."""
    if "scheme = urlparse(url).scheme" not in customer:
        raise ValueError("Original scheme check missing")
    scheme = urlsplit(candidate).scheme
    return {
        "candidate": candidate,
        "current_parser_scheme": scheme,
        "blocked_by_blacklist": scheme in ("file", "gopher", "dict"),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rpc_source", type=Path)
    p.add_argument("customer_source", type=Path)
    p.add_argument("pound_config", type=Path)
    p.add_argument("dockerfile", type=Path)
    args = p.parse_args()
    rpc, customer, proxy, docker = [
        x.read_text(encoding="utf-8") for x in (
            args.rpc_source, args.customer_source,
            args.pound_config, args.dockerfile)
    ]
    validate_sources(customer, rpc, proxy, docker)
    normal, result = reproduce_original_format(rpc)
    print("Original RPC synthetic two-pass format bug reproduced:", MARKER in result)
    print("Ordinary stats page unaffected:", MARKER not in normal)
    print("No hosted flag, SSRF, proxy-smuggling or external service contacted.")


if __name__ == "__main__":
    main()
