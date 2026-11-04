"""Recover PNGs whose fixed-size blocks were round-robin interleaved.

The DUCTF Scrapbooking source writes blocks from images in name-sorted order,
padding the final blocks with zero bytes. This solver reverses the interleave
and trims each recovered PNG exactly after a validated IEND chunk, checking
chunk CRCs rather than merely searching for DUCTF text or hardcoded answers.
"""
import argparse
import struct
import zlib
from pathlib import Path

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

def validate_source(source: str) -> None:
    required = ("block_num * self.block_size", "output.write(f.read(self.block_size))",
                "output.write(b'\\x00' * self.block_size)", "images = sorted(os.listdir")
    # The original source uses these exact source-level operations; don't
    # silently apply this inverse to a different challenge algorithm.
    if not all(fragment in source for fragment in required):
        raise ValueError("Original image interleaving/padding algorithm changed")

def infer_layout(data: bytes, block_size: int = 1024) -> int:
    if block_size < len(PNG_MAGIC):
        raise ValueError("Block too small for PNG signature")
    if len(data) == 0 or len(data) % block_size:
        raise ValueError("Input must contain complete interleaved blocks")
    signatures = [
        i for i in range(0, len(data), block_size)
        if data.startswith(PNG_MAGIC, i)
    ]
    if not signatures or signatures[0] != 0:
        raise ValueError("First PNG is missing at offset zero")
    count = len(signatures)
    expected = [i * block_size for i in range(count)]
    if signatures != expected:
        raise ValueError("PNG start positions are not adjacent first-round blocks")
    if (len(data) // block_size) % count:
        raise ValueError("Incomplete round-robin interleaving")
    return count

def png_valid_length(data: bytes) -> int:
    if not data.startswith(PNG_MAGIC):
        raise ValueError("Missing PNG signature")
    offset = len(PNG_MAGIC)
    first = True
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("Truncated PNG chunk")
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        if length > len(data) - offset - 12:
            raise ValueError("PNG chunk extends beyond file")
        chunk_type = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        expected_crc = struct.unpack(">I", data[offset + 8 + length:offset + 12 + length])[0]
        actual_crc = zlib.crc32(chunk_type + payload) & 0xffffffff
        if actual_crc != expected_crc:
            raise ValueError(f"Corrupt PNG CRC at offset {offset}")
        if first and chunk_type != b"IHDR":
            raise ValueError("First PNG chunk must be IHDR")
        first = False
        offset += 12 + length
        if chunk_type == b"IEND":
            if length != 0:
                raise ValueError("IEND payload must be empty")
            return offset
    raise ValueError("Missing PNG IEND chunk")

def deinterleave(data: bytes, block_size: int = 1024, image_count: int | None = None) -> list[bytes]:
    if image_count is None:
        image_count = infer_layout(data, block_size)
    if image_count < 1 or block_size < 8 or len(data) % (image_count * block_size):
        raise ValueError("Invalid image count, block size or interleave length")
    streams = [bytearray() for _ in range(image_count)]
    for block_no, start in enumerate(range(0, len(data), block_size)):
        streams[block_no % image_count].extend(data[start:start + block_size])
    recovered = []
    for image in streams:
        length = png_valid_length(image)
        if any(image[length:]):
            raise ValueError("Nonzero bytes follow PNG end; unexpected merger output")
        recovered.append(bytes(image[:length]))
    return recovered

def solve(merged_file: Path, output_dir: Path, block_size: int = 1024) -> list[Path]:
    recovered = deinterleave(merged_file.read_bytes(), block_size=block_size)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for i, data in enumerate(recovered):
        path = output_dir / f"image{i}.png"
        path.write_bytes(data)
        paths.append(path)
    return paths

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("merged_image", type=Path)
    p.add_argument("output_directory", type=Path)
    p.add_argument("--block-size", type=int, default=1024)
    args = p.parse_args()
    for path in solve(args.merged_image, args.output_directory, args.block_size):
        print(path)
    print("Recovered PNG files; visual contents must be read separately for the flag.")

if __name__ == "__main__":
    main()
