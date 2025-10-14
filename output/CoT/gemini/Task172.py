def distinctEchoSubstrings(text: str) -> int:
    n = len(text)
    p1, m1 = 31, 10**9 + 7
    p2, m2 = 37, 10**9 + 9

    s_int = [ord(c) - ord('a') + 1 for c in text]

    p1_powers = [1] * (n + 1)
    p2_powers = [1] * (n + 1)
    for i in range(1, n + 1):
        p1_powers[i] = (p1_powers[i - 1] * p1) % m1
        p2_powers[i] = (p2_powers[i - 1] * p2) % m2

    h1 = [0] * (n + 1)
    h2 = [0] * (n + 1)
    for i in range(n):
        h1[i + 1] = (h1[i] * p1 + s_int[i]) % m1
        h2[i + 1] = (h2[i] * p2 + s_int[i]) % m2

    def get_hashes(l, r):
        length = r - l + 1
        hash_a = (h1[r + 1] - (h1[l] * p1_powers[length]) % m1 + m1) % m1
        hash_b = (h2[r + 1] - (h2[l] * p2_powers[length]) % m2 + m2) % m2
        return (hash_a, hash_b)

    found = set()
    for length in range(2, n + 1, 2):
        half = length // 2
        for i in range(n - length + 1):
            h_first = get_hashes(i, i + half - 1)
            h_second = get_hashes(i + half, i + length - 1)

            if h_first == h_second:
                found.add(get_hashes(i, i + length - 1))

    return len(found)

if __name__ == '__main__':
    # Test Case 1
    text1 = "abcabcabc"
    print(f"Test Case 1: text = \"{text1}\", Expected: 3, Got: {distinctEchoSubstrings(text1)}")

    # Test Case 2
    text2 = "leetcodeleetcode"
    print(f"Test Case 2: text = \"{text2}\", Expected: 2, Got: {distinctEchoSubstrings(text2)}")

    # Test Case 3
    text3 = "aaaaa"
    print(f"Test Case 3: text = \"{text3}\", Expected: 2, Got: {distinctEchoSubstrings(text3)}")

    # Test Case 4
    text4 = "ababa"
    print(f"Test Case 4: text = \"{text4}\", Expected: 2, Got: {distinctEchoSubstrings(text4)}")

    # Test Case 5
    text5 = "a"
    print(f"Test Case 5: text = \"{text5}\", Expected: 0, Got: {distinctEchoSubstrings(text5)}")