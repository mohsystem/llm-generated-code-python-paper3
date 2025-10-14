def dna_strand(dna):
    """
    Given one side of a DNA strand, returns the other complementary side.
    'A' and 'T' are complements, 'C' and 'G' are complements.
    
    :param dna: The input DNA strand (e.g., "ATTGC").
    :return: The complementary DNA strand (e.g., "TAACG").
    """
    # Create a translation table
    # 'A' maps to 'T', 'T' to 'A', 'C' to 'G', 'G' to 'C'
    translation_table = str.maketrans('ATCG', 'TAGC')
    
    # Apply the translation to the dna string
    return dna.translate(translation_table)

# Main block with test cases
if __name__ == '__main__':
    test_cases = [
        "ATTGC",
        "GTAT",
        "AAAA",
        "GATTACA",
        "CGCG"
    ]
    
    print("Python Test Cases:")
    for test in test_cases:
        result = dna_strand(test)
        print(f"Input: {test} -> Output: {result}")