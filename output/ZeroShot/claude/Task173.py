
class Task173:
    @staticmethod
    def longestDupSubstring(s):
        def search(length):
            MOD = 2**31 - 1
            base = 26
            hash_val = 0
            power = 1
            seen = {}
            
            for i in range(length):
                hash_val = (hash_val * base + (ord(s[i]) - ord('a'))) % MOD
                if i < length - 1:
                    power = (power * base) % MOD
            
            if hash_val not in seen:
                seen[hash_val] = []
            seen[hash_val].append(0)
            
            for i in range(length, len(s)):
                hash_val = ((hash_val - (ord(s[i - length]) - ord('a')) * power % MOD + MOD) % MOD * base 
                           + (ord(s[i]) - ord('a'))) % MOD
                
                if hash_val in seen:
                    current = s[i - length + 1:i + 1]
                    for idx in seen[hash_val]:
                        if s[idx:idx + length] == current:
                            return current
                
                if hash_val not in seen:
                    seen[hash_val] = []
                seen[hash_val].append(i - length + 1)
            
            return None
        
        n = len(s)
        left, right = 1, n
        result = ""
        
        while left <= right:
            mid = left + (right - left) // 2
            dup = search(mid)
            
            if dup is not None:
                result = dup
                left = mid + 1
            else:
                right = mid - 1
        
        return result

if __name__ == "__main__":
    # Test cases
    print("Test 1:", Task173.longestDupSubstring("banana"))  # "ana"
    print("Test 2:", Task173.longestDupSubstring("abcd"))  # ""
    print("Test 3:", Task173.longestDupSubstring("aa"))  # "a"
    print("Test 4:", Task173.longestDupSubstring("aaaaa"))  # "aaaa"
    print("Test 5:", Task173.longestDupSubstring("abcabcabc"))  # "abcabc"
