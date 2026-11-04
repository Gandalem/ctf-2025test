"""DUCTF 2025 BLAST: invertible byte matrices over Z/256Z.

The original Fortran code accumulates uint8 matrix products modulo 256.
A controlled forward-pass vector and the printed transform matrix can
recover hidden state if the matrix is invertible over Z/256Z. Gaussian
elimination requires an ODD pivot (a unit), not just nonzero pivots.
The original binary's stack out-of-bounds / ROP chain is NOT reproduced
here; no hosted flag is claimed.
"""
import argparse
import re
from pathlib import Path

MOD = 256


def validate_source(source: str) -> None:
    needles = ("UNSIGNED(KIND=UINT8)", "CALL MATVECMUL(B, A, C, M, M, N)",
               "CALL MATVECMUL(B, C, A, M, M, N)", "DO I = 0, M - 1",
               "DO J = 0, P - 1", "DO K = 0, N - 1",
               "C(I, J) = C(I, J) + A(I, K) * B(K, J)",
               "INTEGER, PARAMETER :: M = 16")
    if any(s not in source for s in needles):
        raise ValueError("Original Fortran program changed")


def matrix_multiply(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    if not a or not b or not a[0] or not b[0]:
        raise ValueError("Empty matrix")
    if any(len(row) != len(a[0]) for row in a) or any(len(row) != len(b[0]) for row in b):
        raise ValueError("Ragged matrix")
    if len(a[0]) != len(b):
        raise ValueError("Mismatched dimensions")
    return [[sum(a[i][k] * b[k][j] for k in range(len(b))) % MOD
             for j in range(len(b[0]))] for i in range(len(a))]


def invert_mod256(matrix: list[list[int]]) -> list[list[int]]:
    n = len(matrix)
    if n == 0 or any(len(row) != n for row in matrix):
        raise ValueError("Expected square matrix")
    augmented = [
        [v % MOD for v in row] +
        [int(i == j) for j in range(n)] for i, row in enumerate(matrix)
    ]
    for col in range(n):
        pivot = next((r for r in range(col, n)
                      if augmented[r][col] % 2), None)
        if pivot is None:
            raise ValueError("Singular matrix over Z/256Z (no odd pivot)")
        augmented[col], augmented[pivot] = augmented[pivot], augmented[col]
        unit = pow(augmented[col][col], -1, MOD)
        augmented[col] = [v * unit % MOD for v in augmented[col]]
        for row in range(n):
            if row == col:
                continue
            factor = augmented[row][col]
            augmented[row] = [
                (a - factor * b) % MOD
                for a, b in zip(augmented[row], augmented[col])]
    return [row[n:] for row in augmented]


def apply_transform(matrix: list[list[int]], vector: list[int]) -> list[int]:
    return [row[0] for row in matrix_multiply(matrix, [[v] for v in vector])]


def recover_input(matrix: list[list[int]], output: list[int]) -> list[int]:
    if len(matrix) != len(output):
        raise ValueError("Vector length differs from matrix")
    return apply_transform(invert_mod256(matrix), output)


def column_major_wire(matrix: list[list[int]]) -> list[int]:
    if not matrix or any(len(row) != len(matrix[0]) for row in matrix):
        raise ValueError("Ragged matrix")
    return [matrix[i][j] % MOD
            for j in range(len(matrix[0])) for i in range(len(matrix))]


def local_demo(source: str) -> dict:
    validate_source(source)
    # Synthetic 16x16 triangular invertible matrix, not server random B.
    n = 16
    matrix = [[(1 + 2*i) if i == j else
               ((3*i + 5*j) % 256 if j < i else 0)
               for j in range(n)] for i in range(n)]
    seed = list(range(16))
    transformed = apply_transform(matrix, seed)
    recovered = recover_input(matrix, transformed)
    if recovered != seed:
        raise ValueError("Byte vector inversion failed")
    return {"dimension": n, "recovered_synthetic_vector": recovered,
            "original_binary_exploited": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_fortran", type=Path)
    args = parser.parse_args()
    print(local_demo(args.original_fortran.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
