"""Recover XOR sliced plaintext via repeated-keystream equation graph.

The challenge is underdetermined without external letter guesses ("cribs").
Cribs are exposed explicitly rather than masquerading as computed answers.
"""
import argparse
import re
from collections import deque
from pathlib import Path

DEFAULT_CRIBS = {
    0: "D", 1: "U", 11: "u", 13: "g", 17: "l", 19: "t",
    23: "_", 29: "o", 31: "h", 37: "r", 41: "l",
    43: "r", 47: "w", 53: "l", 59: "y", 61: "f", 67: "f",
}

def extract_ciphertexts(output: str) -> list[bytes]:
    lines = [
        bytes.fromhex(line.strip())
        for line in output.splitlines()
        if re.fullmatch(r"[0-9a-fA-F]{16,}", line.strip())
        and len(line.strip()) % 2 == 0
    ]
    if len(lines) != 7:
        raise ValueError(f"Expected 7 ciphertext lines; got {len(lines)}")
    return lines

def recover(output: str, cribs: dict[int, str] | None = None) -> str:
    ciphertexts = extract_ciphertexts(output)
    total = len(ciphertexts[0])
    if total % 7:
        raise ValueError("Ciphertext length must be divisible by 7")
    flag_len = total // 7
    for stride, ciphertext in enumerate(ciphertexts, start=1):
        if len(ciphertext) != (total + stride - 1) // stride:
            raise ValueError(f"Unexpected ciphertext length for stride {stride}")
    edges: list[list[tuple[int, int]]] = [[] for _ in range(flag_len)]
    # c1[j] = flag[j] XOR key[j]
    # cs[j] = flag[s*j] XOR key[j]
    # hence flag[s*j] XOR flag[j] = c1[j] XOR cs[j].
    for stride in range(2, 8):
        for j, value in enumerate(ciphertexts[stride - 1]):
            endpoint = stride * j
            if endpoint >= flag_len:
                break
            delta = ciphertexts[0][j] ^ value
            edges[j].append((endpoint, delta))
            edges[endpoint].append((j, delta))
    values: list[int | None] = [None] * flag_len
    queue: deque[int] = deque()
    for index, character in (DEFAULT_CRIBS if cribs is None else cribs).items():
        if not (0 <= index < flag_len):
            raise ValueError(f"Crib index outside flag: {index}")
        if len(character) != 1 or ord(character) > 255:
            raise ValueError("Crib must be one byte")
        values[index] = ord(character)
        queue.append(index)
    while queue:
        index = queue.popleft()
        assert values[index] is not None
        for neighbor, delta in edges[index]:
            inferred = values[index] ^ delta
            previous = values[neighbor]
            if previous is None:
                values[neighbor] = inferred
                queue.append(neighbor)
            elif previous != inferred:
                raise ValueError(f"Inconsistent cribs at index {neighbor}")
    if any(x is None for x in values):
        missing = [i for i, value in enumerate(values) if value is None]
        raise ValueError(f"Underdetermined; supply more cribs for indices {missing}")
    return bytes(values).decode("utf-8").strip()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    print(recover(args.input.read_text(encoding="utf-8")))

if __name__ == "__main__":
    main()
