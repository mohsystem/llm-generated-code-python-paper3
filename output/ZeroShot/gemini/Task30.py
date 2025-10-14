def longest(s1, s2):
    """
    Takes two strings s1 and s2 including only letters from a to z.
    Returns a new sorted string, the longest possible, containing distinct letters.
    """
    # Combine the strings, convert to a set to get unique characters,
    # then sort the characters and join them back into a string.
    return "".join(sorted(set(s1 + s2)))

if __name__ == "__main__":
    print("Python Test Cases:")

    # Test Case 1
    s1_1 = "xyaabbbccccdefww"
    s2_1 = "xxxxyyyyabklmopq"
    print(f"Test 1: {longest(s1_1, s2_1)}")  # Expected: "abcdefklmopqwxy"

    # Test Case 2
    s1_2 = "abcdefghijklmnopqrstuvwxyz"
    s2_2 = "abcdefghijklmnopqrstuvwxyz"
    print(f"Test 2: {longest(s1_2, s2_2)}")  # Expected: "abcdefghijklmnopqrstuvwxyz"

    # Test Case 3
    s1_3 = "aretheyhere"
    s2_3 = "yestheyarehere"
    print(f"Test 3: {longest(s1_3, s2_3)}")  # Expected: "aehrsty"

    # Test Case 4
    s1_4 = "loopingisfunbutdangerous"
    s2_4 = "lessdangerousthancoding"
    print(f"Test 4: {longest(s1_4, s2_4)}")  # Expected: "abcdefghilnoprstu"

    # Test Case 5
    s1_5 = "inmanylanguages"
    s2_5 = "theresapairoffunctions"
    print(f"Test 5: {longest(s1_5, s2_5)}")  # Expected: "acefghilmnoprstu"