class Task174:
    @staticmethod
    def shortest_palindrome(s: str) -> str:
        if s is None:
            return ""
        n = len(s)
        if n <= 1:
            return s
        rev = s[::-1]
        combined = s + "#" + rev
        lps = Task174._build_lps(combined)
        prefix_len = lps[-1]
        suffix = s[prefix_len:]
        return suffix[::-1] + s

    @staticmethod
    def _build_lps(p: str):
        lps = [0] * len(p)
        length = 0
        for i in range(1, len(p)):
            while length > 0 and p[i] != p[length]:
                length = lps[length - 1]
            if p[i] == p[length]:
                length += 1
            lps[i] = length
        return lps


if __name__ == "__main__":
    tests = [
        "aacecaaa",
        "abcd",
        "",
        "a",
        "aaab",
    ]
    for t in tests:
        print(Task174.shortest_palindrome(t))