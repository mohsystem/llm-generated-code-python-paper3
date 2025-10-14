
def get_dna_complement(dna):
    if not dna:
        return ""
    
    complement_map = {
        'A': 'T',
        'T': 'A',
        'C': 'G',
        'G': 'C'
    }
    
    complement = []
    
    for nucleotide in dna:
        if nucleotide not in complement_map:
            raise ValueError(f"Invalid DNA nucleotide: {nucleotide}")
        complement.append(complement_map[nucleotide])
    
    return ''.join(complement)


if __name__ == "__main__":
    # Test case 1
    print("Input: ATTGC")
    print(f"Output: {get_dna_complement('ATTGC')}")
    print("Expected: TAACG\\n")
    
    # Test case 2
    print("Input: GTAT")
    print(f"Output: {get_dna_complement('GTAT')}")
    print("Expected: CATA\\n")
    
    # Test case 3
    print("Input: AAAA")
    print(f"Output: {get_dna_complement('AAAA')}")
    print("Expected: TTTT\\n")
    
    # Test case 4
    print("Input: CGCG")
    print(f"Output: {get_dna_complement('CGCG')}")
    print("Expected: GCGC\\n")
    
    # Test case 5
    print("Input: ATCGATCG")
    print(f"Output: {get_dna_complement('ATCGATCG')}")
    print("Expected: TAGCTAGC\\n")
