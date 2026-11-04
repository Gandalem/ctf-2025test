"""Phase 11 independently tests original Scrapbooking and Dualzip algorithms.

This suite uses the previous repository's unittest discovery and fixture data/
convention. All previous ten test files remain unchanged. Synthetic PNG bytes
and ZIP files are generated in memory rather than copying accepted Flag text.
"""
import hashlib
import io
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from solvers import scrapbooking, dualzip

DATA = Path(__file__).resolve().parents[1] / "data"

def chunk(name: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + name + payload
            + struct.pack(">I", zlib.crc32(name + payload) & 0xffffffff))

def sample_png(marker: bytes, fill: int = 0) -> bytes:
    header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xfa\x01\x12\xff")
    return (scrapbooking.PNG_MAGIC + chunk(b"IHDR", header)
            + chunk(b"tEXt", b"Comment\x00" + marker + b"A" * fill)
            + chunk(b"IDAT", pixels) + chunk(b"IEND", b""))

def interleave(originals: list[bytes], block: int = 1024) -> bytes:
    max_rounds = max(len(file) // block for file in originals) + 1
    result = bytearray()
    for r in range(max_rounds):
        for file in originals:
            part = file[r * block:(r + 1) * block]
            result.extend(part.ljust(block, b"\x00"))
    return bytes(result)


class ScrapbookingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_source = (DATA / "scrapbooking_merge_images.py").read_text(encoding="utf-8")
        cls.originals = [
            sample_png(b"FIRST"),
            sample_png(b"SECOND", 1200),
            sample_png(b"THIRD", 2700),
        ]

    def test_original_generator_contract(self):
        scrapbooking.validate_source(self.original_source)

    def test_three_pngs_recovered_byte_exactly(self):
        mixed = interleave(self.originals)
        self.assertEqual(scrapbooking.infer_layout(mixed), 3)
        self.assertEqual(scrapbooking.deinterleave(mixed), self.originals)

    def test_each_png_has_valid_end_and_crc(self):
        for png in self.originals:
            self.assertEqual(scrapbooking.png_valid_length(png), len(png))

    def test_large_blocks_and_different_lengths(self):
        mixed = interleave(self.originals, block=256)
        self.assertEqual(scrapbooking.infer_layout(mixed, 256), 3)
        self.assertEqual(scrapbooking.deinterleave(mixed, 256), self.originals)

    def test_auto_detect_four_images(self):
        originals = self.originals + [sample_png(b"FOURTH", 3500)]
        mixed = interleave(originals)
        self.assertEqual(scrapbooking.infer_layout(mixed), 4)
        self.assertEqual(scrapbooking.deinterleave(mixed), originals)

    def test_reject_corrupt_crc(self):
        broken = bytearray(self.originals[0])
        broken[-5] ^= 0x01
        with self.assertRaisesRegex(ValueError, "CRC"):
            scrapbooking.png_valid_length(broken)

    def test_reject_truncated_png(self):
        with self.assertRaises(ValueError):
            scrapbooking.png_valid_length(self.originals[0][:-12])

    def test_invalid_interleave_rejected(self):
        with self.assertRaises(ValueError):
            scrapbooking.deinterleave(b"not a PNG")

    def test_reject_nonzero_trailing_garbage(self):
        with self.assertRaisesRegex(ValueError, "Nonzero"):
            scrapbooking.deinterleave(interleave([
                self.originals[0] + b"GARBAGE",
                self.originals[1], self.originals[2],
            ]))

    def test_saves_original_images(self):
        with tempfile.TemporaryDirectory() as directory:
            input_file = Path(directory) / "warped.png"
            out = Path(directory) / "images"
            input_file.write_bytes(interleave(self.originals))
            saved = scrapbooking.solve(input_file, out)
            self.assertEqual(len(saved), 3)
            self.assertEqual([p.read_bytes() for p in saved], self.originals)


class DualzipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "dualzip_app.py").read_text(encoding="utf-8")

    def test_original_challenge_routes(self):
        dualzip.validate_source(self.source)

    def test_build_two_stage_local_fixture(self):
        artifact = dualzip.solve(self.source)
        members, target = dualzip.inspect_setup(artifact.setup_zip)
        self.assertEqual(target, b"/ctf-local-marker")
        self.assertEqual(len(members), 2)
        self.assertEqual(members, [artifact.first_name.decode(), artifact.second_name.decode()])

    def test_archive_file_is_valid_zip(self):
        archive = dualzip.build_synthetic_fixture()
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(archive.setup_zip)))
        with zipfile.ZipFile(io.BytesIO(archive.setup_zip)) as z:
            self.assertEqual(len(z.infolist()), 2)
            self.assertEqual(z.read(z.namelist()[1]), b"/ctf-local-marker")

    def test_symlink_unix_mode_and_hash_name(self):
        a = dualzip.build_synthetic_fixture()
        with zipfile.ZipFile(io.BytesIO(a.setup_zip)) as archive:
            node = archive.infolist()[1]
            self.assertEqual((node.external_attr >> 16) & 0o170000, 0o120000)
            self.assertEqual(node.create_system, 3)
        self.assertEqual(a.stem, hashlib.sha256(a.final_zip).hexdigest())
        self.assertEqual(a.second_name, f"../{a.stem}.z02".encode())

    def test_disk_three_eocd(self):
        x = dualzip.build_synthetic_fixture()
        self.assertEqual(x.final_zip[-22:-18], struct.pack("<I", 0x06054B50))
        self.assertEqual(struct.unpack("<H", x.final_zip[-18:-16])[0], 2)

    def test_reject_real_target_paths(self):
        for value in (b"/flag", b"/etc/passwd", b"../../sensitive", b"/ctf-local-a\x00b"):
            with self.assertRaises(ValueError):
                dualzip.build_synthetic_fixture(value)

    def test_reject_changed_extraction_mode(self):
        with self.assertRaisesRegex(ValueError, "differs"):
            dualzip.validate_source(self.source.replace('["unzip", "-:"]', '["unzip"]'))

    def test_general_zip_crc_and_members(self):
        a = dualzip.build_zip([
            dualzip.Entry(b"a.txt", b"alpha"),
            dualzip.Entry(b"b.txt", b"beta"),
        ])
        with zipfile.ZipFile(io.BytesIO(a)) as archive:
            self.assertEqual(archive.testzip(), None)
            self.assertEqual(archive.read("a.txt"), b"alpha")
            self.assertEqual(archive.read("b.txt"), b"beta")

if __name__ == "__main__":
    unittest.main()
