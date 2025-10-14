from typing import Set, Tuple

def distinctEchoSubstrings(text: str) -> int:
    """
    Returns the number of distinct non-empty substrings of text that can be written
    as the concatenation of some string with itself.

    :param text: The input string.
    :return: The number of distinct echo substrings.
    """
    n = len(text)
    if n == 0:
        return 0
    
    # Use double hashing to minimize collisions.
    p1, m1 = 31, 10**9 + 7
    p2, m2 = 37, 10**9 + 9
    
    nums = [ord(c) - ord('a') + 1 for c in text]
    
    p_pow1 = [1] * (n + 1)
    h1 = [0] * (n + 1)
    p_pow2 = [1] * (n + 1)
    h2 = [0] * (n + 1)
    
    for i in range(n):
        p_pow1[i+1] = (p_pow1[i] * p1) % m1
        h1[i+1] = (h1[i] * p1 + nums[i]) % m1
        p_pow2[i+1] = (p_pow2[i] * p2) % m2
        h2[i+1] = (h2[i] * p2 + nums[i]) % m2

    def get_hash(h, p_pow, m, i, j):
        length = j - i
        # hash of text[i..j-1]
        val = (h[j] - (h[i] * p_pow[length]) % m + m) % m
        return val

    distinct_hashes: Set[Tuple[int, int]] = set()
    # length of the full substring 'a+a'
    for length in range(2, n + 1, 2):
        half = length // 2
        for i in range(n - length + 1):
            j = i + half
            k = i + length
            
            h1_a = get_hash(h1, p_pow1, m1, i, j)
            h1_b = get_hash(h1, p_pow1, m1, j, k)
            
            if h1_a == h1_b:
                h2_a = get_hash(h2, p_pow2, m2, i, j)
                h2_b = get_hash(h2, p_pow2, m2, j, k)
                
                if h2_a == h2_b:
                    # Hashes of halves match, confirming an echo substring.
                    # Add the hash of the full substring text[i...k-1] to the set.
                    full_h1 = get_hash(h1, p_pow1, m1, i, k)
                    full_h2 = get_hash(h2, p_pow2, m2, i, k)
                    distinct_hashes.add((full_h1, full_h2))
                    
    return len(distinct_hashes)

if __name__ == "__main__":
    def run_test_case(text: str, expected: int):
        result = distinctEchoSubstrings(text)
        print(f"Input: \"{text}\", Output: {result}")

    run_test_case("abcabcabc", 3)
    run_test_case("leetcodeleetcode", 2)
    run_test_case("abacaba", 0)
    run_test_case("aaaaa", 2)
    run_test_case("aaaaaaaaaa", 4)