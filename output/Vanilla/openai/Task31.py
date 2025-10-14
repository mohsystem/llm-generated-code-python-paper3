def dna_strand(dna: str) -> str:
    return dna.translate(str.maketrans({'A': 'T', 'T': 'A', 'C': 'G', 'G': 'C'}))


if __name__ == "__main__":
    tests = ["ATTGC", "GTAT", "AAAA", "CGCGTTAA", "A"]
    for s in tests:
        print(dna_strand(s))