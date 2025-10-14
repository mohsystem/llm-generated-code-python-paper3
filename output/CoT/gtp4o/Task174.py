# Step 1-5: Secure, efficient implementation using KMP to find longest palindromic prefix.

def shortest_palindrome(s: str) -> str:
    if s is None:
        return ""
    n = len(s)
    if n <= 1:
        return s
    rev = s[::-1]
    combined = s + "#" + rev  # delimiter to avoid overlap
    pi = _prefix_function(combined)
    L = pi[-1]
    return s[L:][::-1] + s

def _prefix_function(t: str):
    n = len(t)
    pi = [0] * n
    for i in range(1, n):
        j = pi[i - 1]
        while j > 0 and t[i] != t[j]:
            j = pi[j - 1]
        if t[i] == t[j]:
            j += 1
        pi[i] = j
    return pi

if __name__ == "__main__":
    tests = [
        "aacecaaa",
        "abcd",
        "",
        "a",
        "aaab"
    ]
    for t in tests:
        res = shortest_palindrome(t)
        print(f'Input: "{t}" -> Output: "{res}"')