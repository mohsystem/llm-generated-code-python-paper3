def countDistinct(text: str) -> int:
    n = len(text)
    if n <= 1:
        return 0

    p1, m1 = 31, 10**9 + 7
    p2, m2 = 37, 10**9 + 9

    p1_powers = [1] * (n + 1)
    p2_powers = [1] * (n + 1)
    for i in range(1, n + 1):
        p1_powers[i] = (p1_powers[i - 1] * p1) % m1
        p2_powers[i] = (p2_powers[i - 1] * p2) % m2

    h1 = [0] * (n + 1)
    h2 = [0] * (n + 1)
    for i in range(n):
        h1[i + 1] = (h1[i] * p1 + (ord(text[i]) - ord('a') + 1)) % m1
        h2[i + 1] = (h2[i] * p2 + (ord(text[i]) - ord('a') + 1)) % m2

    found_hashes = set()
    
    # length is the length of 'a'
    for length in range(1, n // 2 + 1):
        # i is the starting index of 'a+a'
        for i in range(n - 2 * length + 1):
            mid_idx = i + length
            
            # Hash of the first half
            hash1_a = (h1[mid_idx] - (h1[i] * p1_powers[length]) % m1 + m1) % m1
            hash2_a = (h2[mid_idx] - (h2[i] * p2_powers[length]) % m2 + m2) % m2
            
            # Hash of the second half
            hash1_b = (h1[i + 2 * length] - (h1[mid_idx] * p1_powers[length]) % m1 + m1) % m1
            hash2_b = (h2[i + 2 * length] - (h2[mid_idx] * p2_powers[length]) % m2 + m2) % m2

            if hash1_a == hash1_b and hash2_a == hash2_b:
                # Add hash pair of the whole substring 'a+a'
                total_hash1 = (h1[i + 2 * length] - (h1[i] * p1_powers[2 * length]) % m1 + m1) % m1
                total_hash2 = (h2[i + 2 * length] - (h2[i] * p2_powers[2 * length]) % m2 + m2) % m2
                found_hashes.add((total_hash1, total_hash2))

    return len(found_hashes)

if __name__ == '__main__':
    text1 = "abcabcabc"
    print(f"Input: {text1}, Output: {countDistinct(text1)}")

    text2 = "leetcodeleetcode"
    print(f"Input: {text2}, Output: {countDistinct(text2)}")

    text3 = "aaaaa"
    print(f"Input: {text3}, Output: {countDistinct(text3)}")

    text4 = "ababa"
    print(f"Input: {text4}, Output: {countDistinct(text4)}")

    text5 = "zzzzzzzzzz"
    print(f"Input: {text5}, Output: {countDistinct(text5)}")