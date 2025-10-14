
def distinctEchoSubstrings(text):
    distinct_substrings = set()
    n = len(text)
    
    # Try all possible substring lengths (must be even)
    for length in range(2, n + 1, 2):
        half_len = length // 2
        
        # Try all starting positions
        for i in range(n - length + 1):
            first_half = text[i:i + half_len]
            second_half = text[i + half_len:i + length]
            
            if first_half == second_half:
                distinct_substrings.add(text[i:i + length])
    
    return len(distinct_substrings)


if __name__ == "__main__":
    # Test case 1
    print("Test 1:", distinctEchoSubstrings("abcabcabc"))  # Expected: 3
    
    # Test case 2
    print("Test 2:", distinctEchoSubstrings("leetcodeleetcode"))  # Expected: 2
    
    # Test case 3
    print("Test 3:", distinctEchoSubstrings("aa"))  # Expected: 1
    
    # Test case 4
    print("Test 4:", distinctEchoSubstrings("aaaa"))  # Expected: 2
    
    # Test case 5
    print("Test 5:", distinctEchoSubstrings("abcdefg"))  # Expected: 0
