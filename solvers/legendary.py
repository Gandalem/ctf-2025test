"""Legendary: inspect original PHP double URL decoding, HMAC and SQL fields.

Parses the ORIGINAL DUCTF solve.sh payload and verifies original standalone
PHP helper functions through a local PHP CLI interpreter. No MySQL or remote
HTTP requests are made; a synthetic HMAC key is used.
"""
import argparse
import base64
import hashlib
import hmac
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

TEST_KEY = "DUCTF_LOCAL_TEST_KEY"


def parse_original_payload(shell_text: str) -> str:
    found = re.search(r"(?m)^PAYLOAD='([^'\r\n]+)'$", shell_text)
    if not found:
        raise ValueError("Original public Legendary payload missing")
    return found.group(1)


def decode_twice(payload: str) -> str:
    return unquote(unquote(payload))


def hmac_signature(route: str, local_key: str = TEST_KEY) -> str:
    return hmac.new(local_key.encode(), route.encode(), hashlib.sha256).hexdigest()


def escaped_identifier(identifier: str) -> str:
    return "\x60" + identifier.replace("\x60", "\x60\x60") + "\x60"


def extract_php_function(source: str, name: str) -> str:
    # Safely extract only two known standalone helpers; the full file
    # constructs a PDO database connection on import.
    if name not in ("db_escape_col", "api_sig_gen"):
        raise ValueError("Unsupported source function")
    match = re.search(
        r"\bfunction\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{[\s\S]*?\n\}",
        source,
    )
    if not match:
        raise ValueError("Original PHP helper missing: " + name)
    return match.group(0)


def php_local_probe(api_source: str, route: str, field: str, local_key: str = TEST_KEY) -> dict:
    """Execute extracted original PHP helpers with benign local inputs."""
    code = (
        '$argv[1] = base64_decode($argv[1], true);\n'
        '$argv[2] = base64_decode($argv[2], true);\n'
        'define("APP_SECRET_KEY", $argv[3]);\n'
        + extract_php_function(api_source, "db_escape_col")
        + "\n" + extract_php_function(api_source, "api_sig_gen")
        + '\necho json_encode(["escaped" => db_escape_col($argv[2]),'
        ' "signature" => api_sig_gen($argv[1])]);'
    )
    result = subprocess.run(
        ["php", "-r", code, base64.b64encode(route.encode()).decode(),
         base64.b64encode(field.encode()).decode(), local_key],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode:
        raise RuntimeError("Local original PHP helper test failed: " + result.stderr[-800:])
    return json.loads(result.stdout)


def validate_sources(api: str, index: str, nginx: str) -> None:
    must_have = (
        (api, "hash_hmac('sha256', $api, APP_SECRET_KEY)"),
        (api, "str_replace(" + "'\x60', '\x60\x60', $value)"),
        (api, "join(',', array_map('db_escape_col', explode(',', $fields)))"),
        (index, "urldecode(parse_url($_SERVER['PATH_INFO'])['path'])"),
        (nginx, "fastcgi_split_path_info"),
    )
    for src, fragment in must_have:
        if fragment not in src:
            raise ValueError("Original Legendary server contract has changed")


def analyse(shell: str, api: str, index: str, nginx: str) -> dict:
    validate_sources(api, index, nginx)
    payload = parse_original_payload(shell)
    decoded = decode_twice(payload)
    if not decoded.startswith("/api/animal/") or "/fields/" not in decoded:
        raise ValueError("Payload no longer targets expected API route")
    name, fields = decoded[len("/api/animal/"):].split("/fields/", 1)
    if "imagedir from (select" not in name or "0x676c6f623a2f2f2f662a" not in name:
        raise ValueError("Archived original field-selection structure not recognized")
    php = php_local_probe(api, decoded, fields)
    if php["signature"] != hmac_signature(decoded):
        raise ValueError("Local original PHP HMAC differs from Python")
    if php["escaped"] != escaped_identifier(fields):
        raise ValueError("Local original PHP identifier escaping differs")
    return {
        "decoded_route": decoded,
        "route_name": name,
        "route_fields": fields,
        "signature": php["signature"],
        "original_php_identifier": php["escaped"],
        "sql_field_shape": "SELECT " + escaped_identifier(fields)
          + " FROM animals WHERE name = ?",
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("original_solve_script", type=Path)
    p.add_argument("original_api_php", type=Path)
    p.add_argument("original_index_php", type=Path)
    p.add_argument("original_nginx", type=Path)
    args = p.parse_args()
    result = analyse(
        args.original_solve_script.read_text(encoding="utf-8"),
        args.original_api_php.read_text(encoding="utf-8"),
        args.original_index_php.read_text(encoding="utf-8"),
        args.original_nginx.read_text(encoding="utf-8"),
    )
    print("Original PHP route decoded and local HMAC generated")
    print("Original route field count:", len(result["route_fields"]))
    print("Original PHP signed route digest:", result["signature"])
    print("No MySQL, nginx, /flag or remote target access attempted.")


if __name__ == "__main__":
    main()
