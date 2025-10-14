from typing import Set, Tuple

def search(s: str, L: int, n: int) -> int:
    if L == 0:
        return 0
    if L >= n:
        return -1

    base1 = 26
    base2 = 31
    mod1 = 1_000_000_007
    mod2 = 1_000_000_009

    h1 = pow(base1, L - 1, mod1)
    h2 = pow(base2, L - 1, mod2)

    current_hash1 = 0
    current_hash2 = 0
    for i in range(L):
        char_val = ord(s[i]) - ord('a')
        current_hash1 = (current_hash1 * base1 + char_val) % mod1
        current_hash2 = (current_hash2 * base2 + char_val) % mod2

    seen: Set[Tuple[int, int]] = set()
    seen.add((current_hash1, current_hash2))

    for i in range(1, n - L + 1):
        prev_char_val = ord(s[i - 1]) - ord('a')
        next_char_val = ord(s[i + L - 1]) - ord('a')

        current_hash1 = ((current_hash1 - prev_char_val * h1) * base1 + next_char_val) % mod1
        current_hash2 = ((current_hash2 - prev_char_val * h2) * base2 + next_char_val) % mod2

        if (current_hash1, current_hash2) in seen:
            return i
        seen.add((current_hash1, current_hash2))
        
    return -1

def longest_dup_substring(s: str) -> str:
    n = len(s)
    low, high = 1, n
    start = -1
    best_len = 0

    while low <= high:
        mid = low + (high - low) // 2
        if mid == 0:
            low = mid + 1
            continue
        
        found_start = search(s, mid, n)
        if found_start != -1:
            best_len = mid
            start = found_start
            low = mid + 1
        else:
            high = mid - 1

    if start != -1:
        return s[start : start + best_len]
    return ""

if __name__ == '__main__':
    test_cases = [
        "banana",
        "abcd",
        "ababa",
        "mississippi",
        "aaaaaaaaaa"
    ]
    expected_results = [
        "ana",
        "",
        "aba",
        "issi",
        "aaaaaaaaa"
    ]

    for i, s in enumerate(test_cases):
        result = longest_dup_substring(s)
        print(f"Test Case {i + 1}:")
        print(f"Input: s = \"{s}\"")
        print(f"Output: \"{result}\"")
        print(f"Expected: \"{expected_results[i]}\"")
        print()