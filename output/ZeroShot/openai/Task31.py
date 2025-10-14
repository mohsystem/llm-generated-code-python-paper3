def dna_complement(dna: str) -> str:
    if dna is None:
        raise ValueError("Input DNA string cannot be None.")
    if len(dna) == 0:
        raise ValueError("Input DNA string cannot be empty.")
    mapping = {'A': 'T', 'T': 'A', 'C': 'G', 'G': 'C'}
    out_chars = []
    for idx, ch in enumerate(dna):
        up = ch.upper()
        if up not in mapping:
            raise ValueError(f"Invalid DNA character at index {idx}: '{ch}'")
        out_chars.append(mapping[up])
    return ''.join(out_chars)


if __name__ == "__main__":
    tests = [
        "ATTGC",   # TAACG
        "GTAT",    # CATA
        "A",       # T
        "aaaa",    # TTTT
        "gCatTa"   # CGTAAT
    ]
    for t in tests:
        try:
            res = dna_complement(t)
            print(f"Input: {t} -> {res}")
        except ValueError as e:
            print(f"Input: {t} -> Error: {e}")