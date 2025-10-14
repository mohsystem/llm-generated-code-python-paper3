from typing import Dict

def make_complement(dna: str) -> str:
    """
    Returns the complementary DNA strand.
    'A' <-> 'T', 'C' <-> 'G'.
    Handles non-string inputs gracefully by returning an empty string.
    """
    if not isinstance(dna, str):
        return ""
        
    complement_map: Dict[str, str] = {
        'A': 'T',
        'T': 'A',
        'C': 'G',
        'G': 'C'
    }
    
    # Use .get(char, char) to handle any non-DNA characters by leaving them unchanged.
    return "".join([complement_map.get(char, char) for char in dna])

if __name__ == '__main__':
    test_cases = [
        ("ATTGC", "TAACG"),
        ("GTAT", "CATA"),
        ("AAAA", "TTTT"),
        ("GCGC", "CGCG"),
        ("GATTACA", "CTAATGT")
    ]
    
    for i, (input_dna, expected_output) in enumerate(test_cases):
        result = make_complement(input_dna)
        print(f"Test Case {i+1}:")
        print(f"Input:    {input_dna}")
        print(f"Output:   {result}")
        print(f"Expected: {expected_output}")
        print(f"Result:   {'Passed' if result == expected_output else 'Failed'}")
        print("--------------------")