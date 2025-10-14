
def distinctEchoSubstrings(text):
    distinct_substrings = set()
    n = len(text)
    
    # Try all possible substring lengths (must be even)
    for length in range(2, n + 1, 2):
        half_len = length // 2
        
        # Try all possible starting positions
        for i in range(n - length + 1):
            first = text[i:i + half_len]
            second = text[i + half_len:i + length]
            
            if first == second:
                distinct_substrings.add(first + second)
    
    return len(distinct_substrings)


if __name__ == "__main__":
    # Test case 1
    test1 = "abcabcabc"
    print(f'Input: "{test1}"')
    print(f"Output: {distinctEchoSubstrings(test1)}")
    print()
    
    # Test case 2
    test2 = "leetcodeleetcode"
    print(f'Input: "{test2}"')
    print(f"Output: {distinctEchoSubstrings(test2)}")
    print()
    
    # Test case 3
    test3 = "aaaa"
    print(f'Input: "{test3}"')
    print(f"Output: {distinctEchoSubstrings(test3)}")
    print()
    
    # Test case 4
    test4 = "abcdef"
    print(f'Input: "{test4}"')
    print(f"Output: {distinctEchoSubstrings(test4)}")
    print()
    
    # Test case 5
    test5 = "aabbccdd"
    print(f'Input: "{test5}"')
    print(f"Output: {distinctEchoSubstrings(test5)}")
