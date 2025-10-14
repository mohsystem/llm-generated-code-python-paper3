def longest(s1: str, s2: str) -> str:
    """
    Takes two strings s1 and s2 including only letters from a to z.
    Returns a new sorted string, the longest possible, containing distinct letters.
    """
    if not isinstance(s1, str) or not isinstance(s2, str):
        return ""
    
    seen = [False] * 26
    
    for char in s1:
        if 'a' <= char <= 'z':
            seen[ord(char) - ord('a')] = True
            
    for char in s2:
        if 'a' <= char <= 'z':
            seen[ord(char) - ord('a')] = True

    result_chars = []
    for i in range(26):
        if seen[i]:
            result_chars.append(chr(ord('a') + i))
            
    return "".join(result_chars)

# A more Pythonic alternative:
# def longest(s1: str, s2: str) -> str:
#     return "".join(sorted(set(s1 + s2)))

if __name__ == '__main__':
    # Test Case 1
    s1 = "xyaabbbccccdefww"
    s2 = "xxxxyyyyabklmopq"
    print("Test Case 1:")
    print(f's1: "{s1}"')
    print(f's2: "{s2}"')
    print(f'Result: "{longest(s1, s2)}"')
    print('Expected: "abcdefklmopqwxy"\n')

    # Test Case 2
    s1 = "abcdefghijklmnopqrstuvwxyz"
    s2 = "abcdefghijklmnopqrstuvwxyz"
    print("Test Case 2:")
    print(f's1: "{s1}"')
    print(f's2: "{s2}"')
    print(f'Result: "{longest(s1, s2)}"')
    print('Expected: "abcdefghijklmnopqrstuvwxyz"\n')

    # Test Case 3
    s1 = "aretheyhere"
    s2 = "yestheyarehere"
    print("Test Case 3:")
    print(f's1: "{s1}"')
    print(f's2: "{s2}"')
    print(f'Result: "{longest(s1, s2)}"')
    print('Expected: "aehrsty"\n')

    # Test Case 4
    s1 = "loopingisfunbutdangerous"
    s2 = "lessdangerousthancoding"
    print("Test Case 4:")
    print(f's1: "{s1}"')
    print(f's2: "{s2}"')
    print(f'Result: "{longest(s1, s2)}"')
    print('Expected: "abcdefghilnoprstu"\n')

    # Test Case 5
    s1 = "inmanylanguages"
    s2 = "theresapairoffunctions"
    print("Test Case 5:")
    print(f's1: "{s1}"')
    print(f's2: "{s2}"')
    print(f'Result: "{longest(s1, s2)}"')
    print('Expected: "acefghilmnoprstu"\n')