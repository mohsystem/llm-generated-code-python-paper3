
def distinct_echo_substrings(text: str) -> int:
    if not text:
        return 0
    
    # Validate input: only lowercase English letters
    for c in text:
        if not ('a' <= c <= 'z'):
            raise ValueError("Input must contain only lowercase English letters")
    
    distinct_substrings = set()
    n = len(text)
    
    # Iterate through all possible substring lengths (must be even)
    for length in range(2, n + 1, 2):
        half_len = length // 2
        
        # Iterate through all starting positions
        for i in range(n - length + 1):
            first_half = text[i:i + half_len]
            second_half = text[i + half_len:i + length]
            
            if first_half == second_half:
                distinct_substrings.add(text[i:i + length])
    
    return len(distinct_substrings)


def main():
    # Test case 1
    test1 = "abcabcabc"
    print(f'Input: "{test1}" Output: {distinct_echo_substrings(test1)}')
    
    # Test case 2
    test2 = "leetcodeleetcode"
    print(f'Input: "{test2}" Output: {distinct_echo_substrings(test2)}')
    
    # Test case 3
    test3 = "aaaa"
    print(f'Input: "{test3}" Output: {distinct_echo_substrings(test3)}')
    
    # Test case 4
    test4 = "a"
    print(f'Input: "{test4}" Output: {distinct_echo_substrings(test4)}')
    
    # Test case 5
    test5 = "abab"
    print(f'Input: "{test5}" Output: {distinct_echo_substrings(test5)}')


if __name__ == "__main__":
    main()
