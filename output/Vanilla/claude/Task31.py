
def make_complement(dna):
    complement = {'A': 'T', 'T': 'A', 'C': 'G', 'G': 'C'}
    return ''.join(complement[c] for c in dna)

if __name__ == "__main__":
    # Test case 1
    print(f"Input: ATTGC, Output: {make_complement('ATTGC')}")
    
    # Test case 2
    print(f"Input: GTAT, Output: {make_complement('GTAT')}")
    
    # Test case 3
    print(f"Input: AAAA, Output: {make_complement('AAAA')}")
    
    # Test case 4
    print(f"Input: CGCG, Output: {make_complement('CGCG')}")
    
    # Test case 5
    print(f"Input: ATCGATCG, Output: {make_complement('ATCGATCG')}")
