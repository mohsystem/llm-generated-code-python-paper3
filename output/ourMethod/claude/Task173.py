
from typing import Optional

MOD = (1 << 61) - 1
BASE = 26

def longest_dup_substring(s: str) -> str:
    if not s or len(s) < 2 or len(s) > 30000:
        return ""
    
    # Validate input: only lowercase English letters
    for c in s:
        if not ('a' <= c <= 'z'):
            return ""
    
    left = 1
    right = len(s) - 1
    result = ""
    
    while left <= right:
        mid = left + (right - left) // 2
        dup = search(s, mid)
        if dup:
            result = dup
            left = mid + 1
        else:
            right = mid - 1
    
    return result

def search(s: str, length: int) -> Optional[str]:
    if length <= 0 or length > len(s):
        return None
    
    hash_val = 0
    power = 1
    
    for i in range(length):
        hash_val = (hash_val * BASE + (ord(s[i]) - ord('a'))) % MOD
        if i < length - 1:
            power = (power * BASE) % MOD
    
    seen = {hash_val: [0]}
    
    for i in range(1, len(s) - length + 1):
        hash_val = (hash_val - power * (ord(s[i - 1]) - ord('a'))) % MOD
        hash_val = (hash_val * BASE + (ord(s[i + length - 1]) - ord('a'))) % MOD
        
        if hash_val in seen:
            current = s[i:i + length]
            for pos in seen[hash_val]:
                if s[pos:pos + length] == current:
                    return current
        
        if hash_val not in seen:
            seen[hash_val] = []
        seen[hash_val].append(i)
    
    return None

if __name__ == "__main__":
    print(f"Test 1: {longest_dup_substring('banana')}")
    print(f"Test 2: {longest_dup_substring('abcd')}")
    print(f"Test 3: {longest_dup_substring('aa')}")
    print(f"Test 4: {longest_dup_substring('aaaaa')}")
    print(f"Test 5: {longest_dup_substring('abcdefghijklmn')}")
