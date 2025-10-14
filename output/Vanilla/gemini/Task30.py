def longest(s1, s2):
    """
    Takes two strings s1 and s2 including only letters from a to z.
    Returns a new sorted string, the longest possible, containing distinct letters.
    """
    return "".join(sorted(set(s1 + s2)))

if __name__ == '__main__':
    # Test case 1
    result1 = longest("xyaabbbccccdefww", "xxxxyyyyabklmopq")
    print(f"Test 1: {result1}")  # Expected: "abcdefklmopqwxy"

    # Test case 2
    result2 = longest("abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz")
    print(f"Test 2: {result2}")  # Expected: "abcdefghijklmnopqrstuvwxyz"

    # Test case 3
    result3 = longest("aretheyhere", "yestheyarehere")
    print(f"Test 3: {result3}")  # Expected: "aehrsty"

    # Test case 4
    result4 = longest("loopingisfunbutdangerous", "lessdangerousthancoding")
    print(f"Test 4: {result4}")  # Expected: "abcdefghilnoprstu"

    # Test case 5
    result5 = longest("inmanylanguages", "theresapairoffunctions")
    print(f"Test 5: {result5}")  # Expected: "acefghilmnoprstu"