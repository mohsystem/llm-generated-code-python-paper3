from collections import defaultdict

class Task173:
    def longestDupSubstring(self, s: str) -> str:
        n = len(s)
        
        low, high = 1, n
        start, length = -1, 0
        
        while low <= high:
            mid = low + (high - low) // 2
            if mid == 0:
                break
            found_start = self.search(mid, s)
            if found_start != -1:
                length = mid
                start = found_start
                low = mid + 1
            else:
                high = mid - 1
        
        return s[start : start + length] if start != -1 else ""

    def search(self, L: int, s: str) -> int:
        n = len(s)
        if L == 0:
            return 0
        
        base = 26
        modulus = (1 << 61) - 1
        
        h = pow(base, L - 1, modulus)
        
        current_hash = 0
        for i in range(L):
            current_hash = (current_hash * base + (ord(s[i]) - ord('a'))) % modulus
            
        seen = defaultdict(list)
        seen[current_hash].append(0)
        
        for i in range(1, n - L + 1):
            term_to_remove = ((ord(s[i-1]) - ord('a')) * h) % modulus
            current_hash = (current_hash - term_to_remove + modulus) % modulus
            current_hash = (current_hash * base) % modulus
            current_hash = (current_hash + (ord(s[i+L-1]) - ord('a'))) % modulus
            
            if current_hash in seen:
                for start_idx in seen[current_hash]:
                    if s[start_idx : start_idx + L] == s[i : i + L]:
                        return i
            
            seen[current_hash].append(i)
            
        return -1

if __name__ == '__main__':
    solver = Task173()
    test_cases = [
        "banana",
        "abcd",
        "ababab",
        "aaaaa",
        "aabaaabaaaba"
    ]
    for s in test_cases:
        print(f'Input: "{s}"')
        print(f'Output: "{solver.longestDupSubstring(s)}"')
        print()