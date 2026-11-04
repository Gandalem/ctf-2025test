"""DUCTF 2025 fakeobj.py: inspect the CPython object/type pointer layout.

The original challenge overwrites 72 bytes starting at id(obj), replacing
ob_refcnt, ob_type and subsequent storage. Its public exploit points ob_type
to attacker-controlled memory and uses a fake tp_repr pointer at offset 88.

This implementation builds a *synthetic address-space model* and resolves
those pointers, without mutating a live CPython object, invoking system(),
or running a shell. This is a layout demonstration, not hosted Flag recovery.
"""
import argparse
import re
import struct
from dataclasses import dataclass
from pathlib import Path

PAYLOAD_LENGTH = 72
PTR_SIZE = 8
TYPE_REPR_OFFSET = 88
SIMULATED_OBJECT = 0x7000_0000
SIMULATED_FUNCTION = 0x7000_5000
SAFE_MARKER = b".local\x00\x00"


def validate_source(original: str, author_solve: str) -> None:
    expected = (
        "fakeobj_data = bytes.fromhex(input(",
        "for i in range(72):",
        "ctypes.cast(id(obj), ctypes.POINTER(ctypes.c_char))[i]",
        "print(obj)",
    )
    if not all(token in original for token in expected):
        raise ValueError("Original fakeobj overwrite behavior has changed")
    if "p64(addrof_obj - 88 + 16)" not in author_solve or "tp_repr" not in author_solve:
        raise ValueError("Original author fake type strategy not found")


def pack_pointer(value: int) -> bytes:
    if not 0 <= value < 2**64:
        raise ValueError("Expected unsigned 64-bit pointer")
    return struct.pack("<Q", value)


def unpack_pointer(buffer: bytes, offset: int) -> int:
    if offset < 0 or len(buffer) < offset + PTR_SIZE:
        raise ValueError("Missing 64-bit pointer")
    return struct.unpack_from("<Q", buffer, offset)[0]


@dataclass(frozen=True)
class Layout:
    object_address: int
    fake_type_address: int
    function_pointer: int
    overwritten_bytes: bytes
    repr_field_address: int
    simulated_argument: bytes


def build_layout(
    object_address: int = SIMULATED_OBJECT,
    function_pointer: int = SIMULATED_FUNCTION,
    marker: bytes = SAFE_MARKER,
) -> Layout:
    if len(marker) != PTR_SIZE or marker[0] != ord(".") or not marker.endswith(b"\x00"):
        raise ValueError("Only an inert eight-byte local marker is supported")
    if object_address < 0x1000 or object_address % 8:
        raise ValueError("Synthetic object address must be aligned")
    if function_pointer < 0x1000:
        raise ValueError("Invalid synthetic callback pointer")
    # Exactly as in the public solver: ob_type = id(obj) - 88 + 16
    # so fake_type.tp_repr at +88 points to id(obj) + 16.
    fake_type = object_address - TYPE_REPR_OFFSET + 16
    payload = (
        marker
        + pack_pointer(fake_type)
        + pack_pointer(function_pointer)
    ).ljust(PAYLOAD_LENGTH, b"\x00")
    # Reference count increment changes the initial "." byte into "/".
    simulated_argument = bytes([(marker[0] + 1) & 255]) + marker[1:]
    return Layout(object_address, fake_type, function_pointer, payload,
                  fake_type + TYPE_REPR_OFFSET, simulated_argument)


def verify_layout(layout: Layout) -> bool:
    if len(layout.overwritten_bytes) != PAYLOAD_LENGTH:
        raise ValueError("Original overwrite expects 72 bytes")
    if unpack_pointer(layout.overwritten_bytes, 8) != layout.fake_type_address:
        raise ValueError("Incorrect ob_type pointer")
    if layout.repr_field_address != layout.object_address + 16:
        raise ValueError("Fake tp_repr is not placed at the intended address")
    if unpack_pointer(layout.overwritten_bytes, 16) != layout.function_pointer:
        raise ValueError("tp_repr does not point to the inert test callback")
    if layout.simulated_argument[0] != ord("/"):
        raise ValueError("Refcount-byte increment did not occur")
    return True


def simulate_original_overwrite(payload: bytes, address: int = SIMULATED_OBJECT) -> bytes:
    """Copy into *synthetic* bytes to model original ctypes loop, not real memory."""
    if len(payload) < PAYLOAD_LENGTH or address < 0x1000:
        raise ValueError("Invalid original overwrite input")
    original = bytearray(b"\xCC" * 96)
    for i in range(PAYLOAD_LENGTH):
        original[i] = payload[i]
    return bytes(original)


def solve_local(original_source: str, author_solver: str) -> Layout:
    validate_source(original_source, author_solver)
    layout = build_layout()
    verify_layout(layout)
    memory = simulate_original_overwrite(layout.overwritten_bytes)
    if memory[:PAYLOAD_LENGTH] != layout.overwritten_bytes or memory[72:] != b"\xCC" * 24:
        raise ValueError("Unexpected synthetic overwrite")
    return layout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_challenge", type=Path)
    parser.add_argument("original_solver", type=Path)
    args = parser.parse_args()
    layout = solve_local(
        args.original_challenge.read_text(encoding="utf-8"),
        args.original_solver.read_text(encoding="utf-8"),
    )
    print("Synthetic fakeobj 72-byte layout verified:", verify_layout(layout))
    print("Synthetic tp_repr field address:", hex(layout.repr_field_address))
    print("Original process was not corrupted; no system() or hosted Flag.")


if __name__ == "__main__":
    main()
