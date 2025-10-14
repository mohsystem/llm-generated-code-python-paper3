
def distinct_echo_substrings(text):
    # Input validation
    if not text or len(text) > 2000:
        return 0
    
    # Validate that text contains only lowercase English letters
    if not text.islower() or not text.isalpha():
        return 0
    
    distinct_substrings = set()
    n = len(text)
    
    # Iterate through all possible substring lengths (must be even)
    for length in range(2, n + 1, 2):
        half_len = length // 2
        
        # Iterate through all possible starting positions
        for i in range(n - length + 1):
            # Extract the two halves
            first_half = text[i:i + half_len]
            second_half = text[i + half_len:i + length]
            
            # Check if both halves are equal
            if first_half == second_half:
                distinct_substrings.add(first_half + second_half)
    
    return len(distinct_substrings)


def main():
    # Test case 1
    print("Test 1:", distinct_echo_substrings("abcabcabc"))  # Expected: 3
    
    # Test case 2
    print("Test 2:", distinct_echo_substrings("leetcodeleetcode"))  # Expected: 2
    
    # Test case 3
    print("Test 3:", distinct_echo_substrings("aa"))  # Expected: 1
    
    # Test case 4
    print("Test 4:", distinct_echo_substrings("a"))  # Expected: 0
    
    # Test case 5
    print("Test 5:", distinct_echo_substrings("aaaa"))  # Expected: 2


if __name__ == "__main__":
    main()
