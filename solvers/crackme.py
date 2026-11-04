"""Recover DUCTF CrackMe password from Swift constraint checks.

This parses source constraints and solves them, rather than returning a known
flag. It uses no z3 or Swift runtime. The 64-bit hash matches the Swift code.
"""
import argparse
import re
from pathlib import Path

MASK = (1 << 64) - 1

def hash_swift(text: str) -> int:
    hash1, hash2 = 0x811C9DC5, 0x01000193
    for index, byte in enumerate(text.encode("utf-8")):
        hash1 = (((hash1 << 7) | (hash1 >> 57)) ^ byte) & MASK
        hash2 = (hash2 * 33 + byte * (index + 1)) & MASK
    hash2 = ((hash2 << 32) | (hash2 >> 32)) & MASK
    return hash1 ^ hash2

def grab(source: str, pattern: str):
    found = re.search(pattern, source, re.S)
    if not found:
        raise ValueError("Missing Swift challenge constraint: " + pattern[:65])
    return found

def solve_three(equations: list[tuple[int,int,int,int]]) -> str:
    if len(equations) != 3:
        raise ValueError("Expected three linear constraints")
    solutions = []
    a, b, c, target = equations[0]
    for x in range(32, 127):
        for y in range(32, 127):
            remainder = target - a*x - b*y
            if remainder % c:
                continue
            z = remainder // c
            if 32 <= z <= 126 and all(
                i*x + j*y + k*z == value for i,j,k,value in equations
            ):
                solutions.append("".join(map(chr, (x, y, z))))
    if len(solutions) != 1:
        raise ValueError(f"Expected unique linear solution, got {len(solutions)}")
    return solutions[0]

def linear_constraints(source: str, names: tuple[str, str, str]):
    a,b,c=names
    expression = (rf"guard\s+(\d+)\*{a}\s*\+\s*(\d+)\*{b}"
                  rf"\s*\+\s*(\d+)\*{c}\s*==\s*(\d+)")
    return [tuple(map(int, match)) for match in re.findall(expression, source)]

def recover_password(source: str) -> str:
    length = int(grab(source, r"guard password.count == (\d+)")[1])
    result = [None] * length

    def place(index: int, letter: str):
        if index < 0 or index >= length or len(letter) != 1:
            raise ValueError("Invalid recovered index/character")
        if result[index] is not None and result[index] != letter:
            raise ValueError(f"Conflicting Swift constraints at {index}")
        result[index] = letter

    place(0, grab(source, r'guard password.first == "([^"]+)"')[1])
    place(length - 1, grab(source, r'guard password.last == "([^"]+)"')[1])

    # Original Swift code hashes each character at positions 1,4,9,16,25.
    square_table = grab(source, r'guard squareChars == \[([^\]]+)\]')[1]
    hashes = [int(x) for x in re.findall(r'\d+', square_table)]
    for index, expected in enumerate(hashes, 1):
        choices = [chr(c) for c in range(32, 127)
                   if hash_swift(chr(c)) == expected]
        if len(choices) != 1:
            raise ValueError("Unable to uniquely recover hashed character")
        place(index * index, choices[0])

    fixed = re.findall(
        r'guard password\[password.index\(password.startIndex,\s*'
        r'offsetBy:\s*(\d+)\)\]\s*==\s*"([^"]+)"', source,
    )
    for index, letter in fixed:
        place(int(index), letter)

    eq = solve_three(linear_constraints(source, ("v2", "v6", "v8")))
    for index, char in zip((2, 6, 8), eq):
        place(index, char)

    eq = solve_three(linear_constraints(source, ("v14", "v15", "v24")))
    for index, char in zip((14, 15, 24), eq):
        place(index, char)

    reverse_interleaved = grab(
        source, r'guard interleaved == "([^"]+)"'
    )[1][::-1]
    if len(reverse_interleaved) != 8:
        raise ValueError("Unexpected interleaved puzzle width")
    for index, letter in zip((10,20,11,21,12,22,13,23), reverse_interleaved):
        place(index, letter)

    swapped = grab(source, r'guard swapped == "([^"]+)"')[1]
    if len(swapped) != 4:
        raise ValueError("Invalid swapped character puzzle")
    for position, letter in zip((17,16,19,18),
                                (chr(ord(char) + (1 if i%2==0 else -1))
                                 for i,char in enumerate(swapped))):
        place(position, letter)

    place(7, grab(source, r'guard everyOtherChar.first == "([^"]+)"')[1])
    place(5, chr(int(grab(source, r'\.asciiValue!\s*\^\s*0xaa\s*==\s*(\d+)')[1]) ^ 0xaa))
    place(3, chr(int(grab(source, r'\.asciiValue!\s*\+\s*111\s*==\s*(\d+)')[1]) - 111))
    fixed_thirds = grab(source, r'guard every3rdFrom1 == "([^"]+)"')[1]
    if len(fixed_thirds) != 2:
        raise ValueError("Unexpected every-third constraint")
    place(4, fixed_thirds[0])
    place(7, fixed_thirds[1])

    if any(letter is None for letter in result):
        missing = [i for i,x in enumerate(result) if x is None]
        raise ValueError(f"Underdetermined password indices {missing}")
    password = "".join(result)
    checks = grab(source, r'guard password\.h\(\) & 0xffffffff == (\d+)')[1]
    if (hash_swift(password) & 0xffffffff) != int(checks):
        raise ValueError("Forward Swift hash check failed")
    upper = grab(source, r'guard String\(password\.reversed\(\)\)\.h\(\) >> 32 == (\d+)')[1]
    if (hash_swift(password[::-1]) >> 32) != int(upper):
        raise ValueError("Reversed Swift hash check failed")
    return password

def solve(source: str) -> str:
    password = recover_password(source)
    # The Swift wrapper has prefix 'DUCTF{' and a fixed additional '.}' suffix.
    if not grab(source, r'guard s\.hasPrefix\("DU"\)\s*&&\s*s\.hasSuffix\("\.\}"\)'):
        raise ValueError("Unexpected flag wrapper")
    return "DUCTF{" + password + ".}"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("swift_source", type=Path)
    args = parser.parse_args()
    print(solve(args.swift_source.read_text(encoding="utf-8")))

if __name__ == "__main__":
    main()
