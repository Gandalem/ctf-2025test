"""Phase 13 independent forensic regression tests.

Existing 12 test modules are unchanged. Public CTF capture is downloaded by
CI; no external network access occurs from the solver under test.
"""
import base64
import io
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from solvers import fishy_website as fishy, nbd_forensics as nbd

DATA = Path(__file__).resolve().parents[1] / "data"


class FishyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "fishy_client.py").read_text(encoding="utf-8")
        cls.key = fishy.extract_key(cls.source)

    def test_original_client_key_extraction(self):
        self.assertEqual(len(self.key), 32)
        self.assertIn("SECRET =", self.source)

    def test_rc4_round_trip(self):
        original = b"fake TLS application payload"
        self.assertEqual(fishy.rc4(self.key, fishy.rc4(self.key, original)), original)

    def test_tcp_out_of_order_and_retransmission(self):
        self.assertEqual(
            fishy.reassemble([(105, b"world"), (100, b"hello"),
                              (103, b"loworld")]),
            b"helloworld",
        )

    def test_tcp_gap_is_rejected(self):
        with self.assertRaises(ValueError):
            fishy.reassemble([(10, b"hello"), (20, b"world")])

    def test_tls_record_extraction(self):
        data = b"\x16\x03\x01\x00\x00" + b"\x17\x03\x03\x00\x04TEST" + fishy.MARKER
        self.assertEqual(fishy.tls_application_records(data), [b"TEST"])

    def test_synthetic_pcapng_and_tar_exfiltration(self):
        import dpkt
        import struct
        marker = b"DUCTF{SYNTHETIC_PCAP_DATA}"
        archive_buf = io.BytesIO()
        with tarfile.open(fileobj=archive_buf, mode="w:gz") as t:
            payload = marker + b"\n"
            info = tarfile.TarInfo("keys.txt")
            info.size = len(payload)
            t.addfile(info, io.BytesIO(payload))
        encoded = base64.b64encode(archive_buf.getvalue())
        plaintext = b"RESULT: " + encoded
        encrypted = fishy.rc4(self.key, plaintext)
        record = b"\x17\x03\x03" + struct.pack(">H", len(encrypted)) + encrypted
        tcp = dpkt.tcp.TCP(sport=443, dport=12345, seq=100, flags=24, data=record)
        ip = dpkt.ip.IP(
            src=socket.inet_aton(fishy.ATTACKER_IP),
            dst=socket.inet_aton("192.0.2.1"), p=6, ttl=64, data=tcp,
        )
        frame = dpkt.ethernet.Ethernet(
            src=b"\xaa" * 6, dst=b"\xbb" * 6,
            type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
        )
        output = io.BytesIO()
        writer = dpkt.pcapng.Writer(output)
        writer.writepkt(bytes(frame))
        captured_bytes = output.getvalue()
        writer.close()
        self.assertEqual(fishy.solve(captured_bytes, self.source), marker.decode())

    def test_reject_source_without_key(self):
        with self.assertRaises(ValueError):
            fishy.extract_key("print('no secret')")

    def test_actual_original_public_pcap(self):
        pcapfile = os.environ.get("DUCTF_FISHY_PCAP")
        if not pcapfile:
            self.skipTest("PCAP only available in CI via public capture download")
        flag = fishy.solve(Path(pcapfile).read_bytes(), self.source)
        self.assertEqual(flag, "DUCTF{1_gu355_y0u_c4n_d3cRyPT_TLS_tr4ff1c}")


@unittest.skipUnless(shutil.which("mkfs.ext4") and shutil.which("debugfs"),
                     "e2fsprogs required for ext4 integration")
class NBDForensicsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (DATA / "nbd_forensics_main.go").read_text(encoding="utf-8")
        cls.directory = tempfile.TemporaryDirectory(prefix="ctf-ext4-tests-")
        cls.root = Path(cls.directory.name)
        cls.image = cls.root / "challenge.ext4"
        with cls.image.open("wb") as f:
            f.truncate(16 * 1024 * 1024)
        subprocess.run(["mkfs.ext4", "-F", "-q", str(cls.image)],
                       check=True, capture_output=True, timeout=30)
        cls.marker = b"\xff\xd8\xff\xe0DUCTF{SYNTHETIC_JPEG_MARKER}\xff\xd9"
        cls.source_jpeg = cls.root / "synthetic.jpg"
        cls.source_jpeg.write_bytes(cls.marker)
        for command in ("mkdir /nested",
                        f"write {cls.source_jpeg} /nested/f123.jpg",
                        "symlink /flag.jpg nested/f123.jpg"):
            process = subprocess.run(
                ["debugfs", "-w", "-R", command, str(cls.image)],
                capture_output=True, text=True, timeout=20,
            )
            if process.returncode or "Error" in process.stderr:
                raise RuntimeError(f"debugfs fixture creation failed: {process.stderr}")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_original_go_ext4_source_contract(self):
        nbd.validate_source(self.source)

    def test_resolve_real_ext4_symlink_inode(self):
        self.assertEqual(nbd.resolve_flag_symlink(self.image), "/nested/f123.jpg")

    def test_extract_real_ext4_contents(self):
        result = self.root / "output.jpg"
        self.assertEqual(nbd.extract_flag_jpeg(self.image, result), self.marker)
        self.assertEqual(result.read_bytes(), self.marker)

    def test_original_goal_is_a_symlink(self):
        status = nbd.debugfs(self.image, "stat /flag.jpg")
        self.assertIn("symlink", status)

    def test_missing_ext4_image(self):
        with self.assertRaises(ValueError):
            nbd.resolve_flag_symlink(self.root / "missing.ext4")

    def test_challenge_source_change_rejected(self):
        with self.assertRaises(ValueError):
            nbd.validate_source(self.source.replace('Create("flag.jpg"', 'Create("other.jpg"'))

if __name__ == "__main__":
    unittest.main()
