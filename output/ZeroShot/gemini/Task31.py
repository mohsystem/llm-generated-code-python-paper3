def dna_strand(dna: str) -> str:
    """
    Finds the complementary strand of a DNA sequence.
    'A' is complement of 'T', 'C' is complement of 'G'.

    :param dna: A string representing one side of the DNA.
    :return: The complementary DNA strand.
    """
    # Using str.translate is an efficient and Pythonic way to perform character mapping.
    # It creates a translation table from 'ATCG' to 'TAGC' and applies it.
    translation_table = str.maketrans("ATCG", "TAGC")
    return dna.translate(translation_table)

if __name__ == '__main__':
    test_cases = ["ATTGC", "GTAT", "AAAA", "CGCG", "TAACG"]
    
    for test_case in test_cases:
        result = dna_strand(test_case)
        print(f'"{test_case}" --> "{result}"')