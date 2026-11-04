"""Offline DUCTF 2025 Fishy Website packet-capture analysis.

Reads a *public CTF PCAPNG* and the published Python client as static data.
It does not execute PowerShell, Python from the capture, or any C2 commands.
Reassemble TCP segments, identify fake TLS application records, decrypt
each independent RC4 record, and recover a Base64/gzip/tar file from the
transcript. No sockets are opened by this module.
"""
import argparse
import ast
import base64
import io
import ipaddress
import re
import tarfile
from collections import defaultdict
from pathlib import Path

ATTACKER_IP = "20.5.48.200"
MAGIC = b"\x17\x03\x03"
MARKER = b"\x02\x04\x06\x08"


def extract_key(client_source: str) -> bytes:
    match = re.search(r"(?m)^SECRET\s*=\s*(b[\"'][^\r\n]+[\"'])", client_source)
    if not match:
        raise ValueError("Public CTF client has no SECRET byte literal")
    value = ast.literal_eval(match.group(1))
    if not isinstance(value, bytes) or len(value) < 16:
        raise ValueError("Unexpected challenge RC4 key")
    return value


def rc4(key: bytes, ciphertext: bytes) -> bytes:
    if not key:
        raise ValueError("Empty RC4 key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 255
        state[i], state[j] = state[j], state[i]
    i = j = 0
    out = bytearray()
    for value in ciphertext:
        i = (i + 1) & 255
        j = (j + state[i]) & 255
        state[i], state[j] = state[j], state[i]
        out.append(value ^ state[(state[i] + state[j]) & 255])
    return bytes(out)


def reassemble(segments: list[tuple[int, bytes]]) -> bytes:
    """Reassemble one direction of a captured TCP conversation.

    Deduplicate retransmissions and overlapping segments. A sequence gap
    is an error rather than silently concatenating incorrect plaintext.
    """
    if not segments:
        return b""
    ordered = sorted(segments, key=lambda x: (x[0], -len(x[1])))
    output = bytearray()
    origin = ordered[0][0]
    for sequence, part in ordered:
        offset = sequence - origin
        if offset > len(output):
            raise ValueError("Missing TCP stream bytes")
        if offset < 0:
            raise ValueError("Unordered TCP origin")
        overlap = len(output) - offset
        if overlap > 0 and output[offset:offset + min(overlap, len(part))] != part[:overlap]:
            raise ValueError("Conflicting TCP retransmission bytes")
        if overlap < len(part):
            output.extend(part[overlap:])
    return bytes(output)


def packets_by_flow(pcapng: bytes, attacker: str = ATTACKER_IP) -> dict[tuple, bytes]:
    import dpkt
    import socket
    flows = defaultdict(list)
    reader = dpkt.pcapng.Reader(io.BytesIO(pcapng))
    target = ipaddress.ip_address(attacker)
    for _, raw in reader:
        try:
            frame = dpkt.ethernet.Ethernet(raw)
            ip = frame.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP) or not tcp.data:
                continue
            source = ipaddress.ip_address(ip.src)
            destination = ipaddress.ip_address(ip.dst)
            if target not in (source, destination):
                continue
            if tcp.sport != 443 and tcp.dport != 443:
                continue
            flow = (str(source), int(tcp.sport), str(destination), int(tcp.dport))
            flows[flow].append((tcp.seq, bytes(tcp.data)))
        except (ValueError, TypeError, dpkt.dpkt.UnpackError):
            continue
    return {flow: reassemble(segments) for flow, segments in flows.items()}


def tls_application_records(stream: bytes) -> list[bytes]:
    """Skip fake handshake bytes, parse TLS 0x17/0x0303 record lengths."""
    records = []
    pos = 0
    while pos + 5 <= len(stream):
        start = stream.find(MAGIC, pos)
        if start < 0 or start + 5 > len(stream):
            break
        size = int.from_bytes(stream[start + 3:start + 5], "big")
        end = start + 5 + size
        if size == 0 or end > len(stream):
            pos = start + 1
            continue
        records.append(stream[start + 5:end])
        pos = end
    return records


def decrypted_transcript(pcapng: bytes, key: bytes,
                         attacker: str = ATTACKER_IP) -> list[tuple[str, bytes]]:
    conversations = packets_by_flow(pcapng, attacker)
    output = []
    for flow, stream in conversations.items():
        direction = "to-attacker" if flow[2] == attacker else "from-attacker"
        for record in tls_application_records(stream):
            candidate = record[:-4] if record.endswith(MARKER) else record
            plaintext = rc4(key, candidate)
            output.append((direction, plaintext))
    if not output:
        raise ValueError("No encrypted fake-TLS application records found")
    return output


def extract_tar_flag(transcript: list[tuple[str, bytes]]) -> str:
    """Extract only regular text files from a Base64 gzip/tar CTF transcript."""
    encoded = []
    for _, plaintext in transcript:
        encoded.extend(re.findall(rb"H4sI[A-Za-z0-9+/=]{80,}", plaintext))
    for text in encoded:
        try:
            raw = base64.b64decode(text, validate=True)
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
                for member in archive:
                    if (not member.isfile() or member.size > 100000
                            or Path(member.name).name != "keys.txt"):
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        continue
                    data = stream.read()
                    match = re.search(rb"DUCTF\{[ -~]{1,200}?\}", data)
                    if match:
                        return match.group().decode("ascii")
        except (ValueError, OSError, tarfile.TarError):
            continue
    raise ValueError("No exfiltrated CTF keys.txt flag found in transcript")


def solve(pcap: bytes, client_source: str) -> str:
    return extract_tar_flag(decrypted_transcript(pcap, extract_key(client_source)))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("pcapng", type=Path)
    p.add_argument("original_client_source", type=Path)
    args = p.parse_args()
    print(solve(args.pcapng.read_bytes(),
                args.original_client_source.read_text(encoding="utf-8")))

if __name__ == "__main__":
    main()
