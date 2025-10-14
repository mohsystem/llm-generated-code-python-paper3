# Python implementation
# Chain-of-Through process (high-level):
# 1) Understand: return DNA complement.
# 2) Security: validate type and characters.
# 3) Secure coding: explicit mapping, exceptions for invalid input.
# 4) Review: no eval/exec, no external deps.
# 5) Output: function returns string; tests provided.

from typing import Optional

def dna_complement(dna: str) -> str:
    if not isinstance(dna, str):
        raise ValueError("Input DNA must be a string")
    mapping = {
        'A': 'T', 'T': 'A', 'C': 'G', 'G': 'C',
        'a': 'T', 't': 'A', 'c': 'G', 'g': 'C'
    }
    out_chars = []
    for i, ch in enumerate(dna):
        if ch in mapping:
            out_chars.append(mapping[ch])
        else:
            raise ValueError(f"Invalid DNA character at index {i}: {ch!r}")
    return ''.join(out_chars)

# 5 test cases
if __name__ == "__main__":
    tests = [
        "ATTGC",
        "GTAT",
        "A",
        "GATTACA",
        "CCGGTTAA"
    ]
    for t in tests:
        try:
            print(f"{t} -> {dna_complement(t)}")
        except ValueError as e:
            print(f"Error for {t!r}: {e}")