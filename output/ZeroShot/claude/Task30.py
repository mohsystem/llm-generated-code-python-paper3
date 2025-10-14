
def longest(s1, s2):
    if s1 is None or s2 is None:
        return ""
    
    unique_chars = set()
    
    for c in s1:
        if 'a' <= c <= 'z':
            unique_chars.add(c)
    
    for c in s2:
        if 'a' <= c <= 'z':
            unique_chars.add(c)
    
    return ''.join(sorted(unique_chars))


if __name__ == "__main__":
    # Test case 1
    a1 = "xyaabbbccccdefww"
    b1 = "xxxxyyyyabklmopq"
    print(f"Test 1: {longest(a1, b1)}")
    
    # Test case 2
    a2 = "abcdefghijklmnopqrstuvwxyz"
    b2 = "abcdefghijklmnopqrstuvwxyz"
    print(f"Test 2: {longest(a2, b2)}")
    
    # Test case 3
    a3 = "aretheyhere"
    b3 = "yestheyarehere"
    print(f"Test 3: {longest(a3, b3)}")
    
    # Test case 4
    a4 = "loopingisfunbutdangerous"
    b4 = "lessdangerousthancoding"
    print(f"Test 4: {longest(a4, b4)}")
    
    # Test case 5
    a5 = ""
    b5 = "abc"
    print(f"Test 5: {longest(a5, b5)}")
