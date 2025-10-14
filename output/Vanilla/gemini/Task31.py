def dna_strand(dna):
    """
    Returns the complementary DNA strand.
    'A' <-> 'T', 'C' <-> 'G'
    """
    return dna.translate(str.maketrans("ATCG", "TAGC"))

if __name__ == '__main__':
    test_cases = ["ATTGC", "GTAT", "AAAA", "CGCG", "TAGCTAGC"]
    for test in test_cases:
        print(f"Input: {test} --> Output: {dna_strand(test)}")