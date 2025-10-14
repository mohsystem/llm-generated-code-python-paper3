
def get_dna_complement(dna: str) -> str:
    if dna is None:
        raise ValueError("DNA string cannot be None")
    
    if not isinstance(dna, str):
        raise TypeError("DNA must be a string")
    
    if len(dna) == 0:
        raise ValueError("DNA string cannot be empty")
    
    if len(dna) > 1000000:
        raise ValueError("DNA string too long")
    
    complement_map = {
        'A': 'T',
        'T': 'A',
        'C': 'G',
        'G': 'C'
    }
    
    complement = []
    for nucleotide in dna:
        if nucleotide not in complement_map:
            raise ValueError(f"Invalid nucleotide: {nucleotide}")
        complement.append(complement_map[nucleotide])
    
    return ''.join(complement)


if __name__ == "__main__":
    test_cases = ["ATTGC", "GTAT", "AAAA", "CGCG", "ATCGATCG"]
    expected = ["TAACG", "CATA", "TTTT", "GCGC", "TAGCTAGC"]
    
    for i in range(len(test_cases)):
        result = get_dna_complement(test_cases[i])
        print(f"Input: {test_cases[i]} -> Output: {result} (Expected: {expected[i]}, Pass: {result == expected[i]})")
