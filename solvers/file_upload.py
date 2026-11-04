"""DUCTF 2025 file-upload: original Flask upload and file-view route analysis.

The app separates the authenticated upload origin from the file-serving
origin. Its viewer infers MIME from user-controlled bytes, rather than
enforcing inert downloads. This local reproduction uses only benign HTML,
never fetches administrator cookies or contacts a hosted challenge.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import os
import re
import subprocess
import tempfile
from pathlib import Path

TEST_MARKER = "DUCTF_LOCAL_UPLOAD_PROOF"


def validate_source(upload_source: str, view_source: str) -> None:
    fragments = (
        (upload_source, "f.save("),
        (upload_source, "h(session['user'])"),
        (upload_source, "@app.route('/open_file')"),
        (upload_source, "@app.route('/upload', methods="),
        (view_source, 'subprocess.run(["file", "-b", "-i", safe_path]'),
        (view_source, "Response(file_data, mimetype=mime_type)"),
        (view_source, '"X-Frame-Options"'),
    )
    for source, fragment in fragments:
        if fragment not in source:
            raise ValueError("Original upload/view source has changed")


def benign_html(marker: str = TEST_MARKER) -> bytes:
    if not re.fullmatch(r"[A-Z0-9_]{8,80}", marker):
        raise ValueError("Only a literal local proof marker is supported")
    # No URLs, worker registration, cookie access or bot report endpoint.
    return (
        '<!doctype html><html><head><title>Local upload proof</title></head>'
        '<body><div id="result"></div><script>'
        'document.querySelector("#result").textContent = "' + marker + '";'
        '</script></body></html>'
    ).encode("ascii")


def load_original(upload_file: Path, template_dir: Path):
    if not template_dir.is_dir():
        raise ValueError("Original dashboard template directory missing")
    spec = importlib.util.spec_from_file_location(
        "_ductf_file_upload_local", upload_file.resolve())
    if spec is None or spec.loader is None:
        raise ValueError("Could not load original public Flask source")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.app.template_folder = str(template_dir.resolve())
    module.app.config.update(TESTING=True)
    return module


@contextlib.contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(previous)


def original_upload_demo(
    upload_file: Path, view_file: Path, template_dir: Path,
    marker: str = TEST_MARKER,
) -> tuple[str, str, str]:
    validate_source(
        upload_file.read_text(encoding="utf-8"),
        view_file.read_text(encoding="utf-8"))
    module = load_original(upload_file, template_dir)
    with tempfile.TemporaryDirectory(prefix="ductf-file-upload-") as temporary:
        root = Path(temporary)
        with working_directory(root):
            with module.app.test_client() as client:
                with client.session_transaction() as session:
                    session["user"] = "synthetic_user"
                response = client.post(
                    "/upload",
                    data={"file": (io.BytesIO(benign_html(marker)), "proof.html")},
                    content_type="multipart/form-data",
                )
                if response.status_code not in (302, 303):
                    raise ValueError("Original upload rejected local test")
                files = list((root / "uploads").iterdir())
                if len(files) != 1:
                    raise ValueError("Original upload did not save exactly one file")
                path = files[0]
                prefix = hashlib.sha256(b"synthetic_user").hexdigest() + "-"
                if not path.name.startswith(prefix):
                    raise ValueError("Unexpected uploaded-file name")
                page = client.get("/")
                if path.name not in page.get_data(as_text=True):
                    raise ValueError("Original dashboard did not list upload")
                redirect = client.get("/open_file?id=1")
                if redirect.status_code not in (302, 303):
                    raise ValueError("Original file-open route did not redirect")
                destination = redirect.headers.get("Location", "")
                if not destination.endswith("/" + path.name):
                    raise ValueError("Original file redirect did not match upload")
                # Use the exact original viewer MIME command with only a
                # freshly generated, harmless local HTML file.
                result = subprocess.run(
                    ["file", "-b", "-i", str(path)],
                    capture_output=True, text=True, timeout=10, check=True,
                )
                return path.name, destination, result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upload_source", type=Path)
    parser.add_argument("viewer_source", type=Path)
    parser.add_argument("template_dir", type=Path)
    args = parser.parse_args()
    name, location, mime = original_upload_demo(
        args.upload_source, args.viewer_source, args.template_dir)
    print("Original Flask upload accepted local HTML:", name)
    print("File-view redirect:", location)
    print("Viewer MIME detection:", mime)
    print("No hosted flag, service worker, or exfiltration attempted.")


if __name__ == "__main__":
    main()
