"""Offline ext4 disk-image forensics for DUCTF Network Disk Forensics.

The original 2025 Go challenge serves an ext4 disk over NBD and creates
/flag.jpg as a symlink to a JPEG at a randomly nested path. This safe,
non-root solver operates ONLY on an already acquired local ext4 image:
it resolves the image's symlink inode with debugfs and dumps its target
file. NBD network acquisition and OCR of the JPEG are out of scope.
No actual CTF remote host is contacted.
"""
import argparse
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath


def validate_source(source: str) -> None:
    required = (
        r'generateFilesystem\(flag string, levels int',
        r'challengeDir\.Create\("flag\.jpg",\s*symlink\)',
        r'filesystem\.Factory\.NewSymlink',
        r'filesystemToExt4\(fs filesystem\.Directory\)',
        r'gonbd\.Handle\(',
    )
    if any(re.search(pattern, source) is None for pattern in required):
        raise ValueError("Original ext4/NBD challenge behavior changed")


def debugfs(image: Path, instruction: str) -> str:
    binary = shutil.which("debugfs")
    if not binary:
        raise RuntimeError("debugfs is required; install e2fsprogs")
    if not image.is_file():
        raise ValueError("Disk image does not exist")
    process = subprocess.run(
        [binary, "-R", instruction, str(image.resolve())],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if process.returncode != 0 or "File not found" in process.stderr:
        raise ValueError("debugfs could not read requested ext4 inode: "
                         + process.stderr[-500:])
    return process.stdout


def resolve_flag_symlink(image: Path) -> str:
    status = debugfs(image, "stat /flag.jpg")
    if not re.search(r"Type:\s+symlink", status):
        raise ValueError("Original /flag.jpg is not an ext4 symlink")
    found = re.search(r'Fast link dest:\s*"([^"]+)"', status)
    if not found:
        raise ValueError("Could not resolve short inline ext4 symlink target")
    original = PurePosixPath(found.group(1))
    if original.is_absolute() or ".." in original.parts or not original.parts:
        raise ValueError("Unsafe or unexpected symlink target path")
    return "/" + str(original)


def extract_flag_jpeg(image: Path, output_file: Path) -> bytes:
    target = resolve_flag_symlink(image)
    with tempfile.TemporaryDirectory(prefix="ductf-ext4-dump-") as temp:
        path = Path(temp) / "flag.jpg"
        # Debugfs dump does not execute or mount the disk image.
        debugfs(image, f"dump {target} {path}")
        if not path.is_file():
            raise ValueError("Referenced ext4 JPEG inode could not be extracted")
        contents = path.read_bytes()
        if not contents:
            raise ValueError("Recovered target file is empty")
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_bytes(contents)
        return contents


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("local_ext4_image", type=Path)
    parser.add_argument("jpeg_output_file", type=Path)
    args = parser.parse_args()
    raw = extract_flag_jpeg(args.local_ext4_image, args.jpeg_output_file)
    print(f"Recovered linked file: {args.jpeg_output_file} ({len(raw)} bytes)")
    print("This does not perform remote NBD acquisition or decode the image text.")


if __name__ == "__main__":
    main()
