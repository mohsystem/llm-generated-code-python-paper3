def distinctEchoSubstrings(text: str) -> int:
    """
    Calculates the number of distinct non-empty substrings that can be written
    as the concatenation of some string with itself.
    :param text: The input string.
    :return: The number of such distinct substrings.
    """
    P1, M1 = 31, 10**9 + 7
    P2, M2 = 37, 10**9 + 9
    n = len(text)

    p_pow1 = [1] * (n + 1)
    h1 = [0] * (n + 1)
    p_pow2 = [1] * (n + 1)
    h2 = [0] * (n + 1)

    for i in range(n):
        p_pow1[i+1] = (p_pow1[i] * P1) % M1
        h1[i+1] = (h1[i] * P1 + ord(text[i]) - ord('a') + 1) % M1
        p_pow2[i+1] = (p_pow2[i] * P2) % M2
        h2[i+1] = (h2[i] * P2 + ord(text[i]) - ord('a') + 1) % M2

    def get_hash(h, p_pow, M, i, j):
        length = j - i + 1
        term = (h[i] * p_pow[length]) % M
        raw_hash = h[j + 1] - term
        return (raw_hash % M + M) % M

    found_hashes = set()
    for l in range(1, n // 2 + 1): # l is the length of the repeating part 'a'
        for i in range(n - 2 * l + 1): # i is the start of 'a+a'
            j = i + l # j is the start of the second 'a'
            
            # Compare text[i...i+l-1] and text[j...j+l-1] using double hashing
            h1_a = get_hash(h1, p_pow1, M1, i, i + l - 1)
            h1_b = get_hash(h1, p_pow1, M1, j, j + l - 1)
            
            if h1_a == h1_b:
                h2_a = get_hash(h2, p_pow2, M2, i, i + l - 1)
                h2_b = get_hash(h2, p_pow2, M2, j, j + l - 1)
                
                if h2_a == h2_b:
                    # Strings are very likely equal. Add the hash of the 'a+a' substring.
                    hash_aa_1 = get_hash(h1, p_pow1, M1, i, i + 2*l - 1)
                    hash_aa_2 = get_hash(h2, p_pow2, M2, i, i + 2*l - 1)
                    found_hashes.add((hash_aa_1, hash_aa_2))

    return len(found_hashes)

if __name__ == '__main__':
    test_cases = [
        "abcabcabc",       # Expected: 3
        "leetcodeleetcode",# Expected: 2
        "a",               # Expected: 0
        "aaaaa",           # Expected: 2
        "abacaba"          # Expected: 0
    ]
    
    for i, text in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        result = distinctEchoSubstrings(text)
        print(f'Input: text = "{text}"')
        print(f"Output: {result}\n")