
def longest(s1, s2):
    if s1 is None or s2 is None:
        return ""
    
    seen = [False] * 26
    
    for c in s1:
        if 'a' <= c <= 'z':
            seen[ord(c) - ord('a')] = True
    
    for c in s2:
        if 'a' <= c <= 'z':
            seen[ord(c) - ord('a')] = True
    
    result = []
    for i in range(26):
        if seen[i]:
            result.append(chr(ord('a') + i))
    
    return ''.join(result)

if __name__ == "__main__":
    # Test case 1
    a1 = "xyaabbbccccdefww"
    b1 = "xxxxyyyyabklmopq"
    print("Test 1:", longest(a1, b1))
    
    # Test case 2
    a2 = "abcdefghijklmnopqrstuvwxyz"
    print("Test 2:", longest(a2, a2))
    
    # Test case 3
    a3 = "abc"
    b3 = "xyz"
    print("Test 3:", longest(a3, b3))
    
    # Test case 4
    a4 = "zzz"
    b4 = "aaa"
    print("Test 4:", longest(a4, b4))
    
    # Test case 5
    a5 = ""
    b5 = "abc"
    print("Test 5:", longest(a5, b5))
