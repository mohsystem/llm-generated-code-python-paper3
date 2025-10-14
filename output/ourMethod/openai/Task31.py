from typing import List

MAX_LEN = 10_000_000

def dna_complement(s: str) -> str:
    if not isinstance(s, str):
        raise TypeError("Input DNA must be a string.")
    if len(s) == 0:
        raise ValueError("Input DNA must be non-empty.")
    if len(s) > MAX_LEN:
        raise ValueError("Input DNA length exceeds maximum allowed.")
    s_up = s.upper()
    allowed = set("ATCG")
    if not set(s_up).issubset(allowed):
        bad = sorted(set(ch for ch in s if ch.upper() not in allowed))
        raise ValueError(f"Invalid DNA base(s) found: {''.join(bad)}")
    trans = str.maketrans("ATCG", "TAGC")
    return s_up.translate(trans)

def main() -> None:
    tests: List[str] = [
        "ATTGC",
        "GTAT",
        "AAAA",
        "CGCGTTAA",
        "acgtACGT",
    ]
    for t in tests:
        try:
            print(f"Input: {t} => Output: {dna_complement(t)}")
        except Exception as e:
            print(f"Input: {t} => Error: {e}")

if __name__ == "__main__":
    main()