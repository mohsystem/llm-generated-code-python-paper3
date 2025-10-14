
class Solution:
    def longestDupSubstring(self, s: str) -> str:
        if not s or len(s) < 2:
            return ""
        
        MOD = 10**9 + 7
        BASE = 26
        
        def search(length):
            if length <= 0 or length > len(s):
                return ""
            
            hash_val = 0
            pow_val = 1
            
            for i in range(length):
                hash_val = (hash_val * BASE + (ord(s[i]) - ord('a'))) % MOD
                if i < length - 1:
                    pow_val = (pow_val * BASE) % MOD
            
            seen = {hash_val: [0]}
            
            for i in range(length, len(s)):
                hash_val = ((hash_val - (ord(s[i - length]) - ord('a')) * pow_val % MOD + MOD) % MOD * BASE + (ord(s[i]) - ord('a'))) % MOD
                
                if hash_val in seen:
                    current = s[i - length + 1:i + 1]
                    for idx in seen[hash_val]:
                        if s[idx:idx + length] == current:
                            return current
                
                if hash_val not in seen:
                    seen[hash_val] = []
                seen[hash_val].append(i - length + 1)
            
            return ""
        
        left, right = 1, len(s)
        result = ""
        
        while left <= right:
            mid = left + (right - left) // 2
            dup = search(mid)
            if dup:
                result = dup
                left = mid + 1
            else:
                right = mid - 1
        
        return result

def longestDupSubstring(s: str) -> str:
    solution = Solution()
    return solution.longestDupSubstring(s)

if __name__ == "__main__":
    print("Test 1:", longestDupSubstring("banana"))
    print("Test 2:", longestDupSubstring("abcd"))
    print("Test 3:", longestDupSubstring("aa"))
    print("Test 4:", longestDupSubstring("aaaaa"))
    print("Test 5:", longestDupSubstring("abcabcabc"))
