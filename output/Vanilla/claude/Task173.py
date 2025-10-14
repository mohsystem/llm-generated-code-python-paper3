
class Task173:
    @staticmethod
    def longestDupSubstring(s):
        def search(length):
            mod = 2**32
            base = 26
            hash_val = 0
            pow_val = 1
            
            for i in range(length):
                hash_val = (hash_val * base + (ord(s[i]) - ord('a'))) % mod
                if i < length - 1:
                    pow_val = (pow_val * base) % mod
            
            seen = {hash_val}
            
            for i in range(length, len(s)):
                hash_val = (hash_val * base - (ord(s[i - length]) - ord('a')) * pow_val % mod + mod) % mod
                hash_val = (hash_val + (ord(s[i]) - ord('a'))) % mod
                
                if hash_val in seen:
                    return s[i - length + 1:i + 1]
                seen.add(hash_val)
            
            return None
        
        n = len(s)
        left, right = 1, n
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

if __name__ == "__main__":
    # Test cases
    print("Test 1:", Task173.longestDupSubstring("banana"))  # Expected: "ana"
    print("Test 2:", Task173.longestDupSubstring("abcd"))  # Expected: ""
    print("Test 3:", Task173.longestDupSubstring("aa"))  # Expected: "a"
    print("Test 4:", Task173.longestDupSubstring("aaaaa"))  # Expected: "aaaa"
    print("Test 5:", Task173.longestDupSubstring("abcabcabc"))  # Expected: "abcabc"
