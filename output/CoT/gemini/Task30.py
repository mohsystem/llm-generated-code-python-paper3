def longest(s1, s2):
    """
    Takes 2 strings s1 and s2 including only letters from a to z.
    Returns a new sorted string, the longest possible, containing distinct letters.
    """
    # Combine the two strings, create a set to get unique characters,
    # then sort the characters and join them to form the final string.
    return "".join(sorted(set(s1 + s2)))

# Main execution block with test cases
if __name__ == '__main__':
    # Test Case 1
    a1 = "xyaabbbccccdefww"
    b1 = "xxxxyyyyabklmopq"
    print("Test Case 1:")
    print(f's1: "{a1}"')
    print(f's2: "{b1}"')
    print(f'Result: "{longest(a1, b1)}"') # Expected: "abcdefklmopqwxy"
    print()

    # Test Case 2
    a2 = "abcdefghijklmnopqrstuvwxyz"
    b2 = "abcdefghijklmnopqrstuvwxyz"
    print("Test Case 2:")
    print(f's1: "{a2}"')
    print(f's2: "{b2}"')
    print(f'Result: "{longest(a2, b2)}"') # Expected: "abcdefghijklmnopqrstuvwxyz"
    print()
    
    # Test Case 3
    a3 = "aretheyhere"
    b3 = "yestheyarehere"
    print("Test Case 3:")
    print(f's1: "{a3}"')
    print(f's2: "{b3}"')
    print(f'Result: "{longest(a3, b3)}"') # Expected: "aehrsty"
    print()

    # Test Case 4
    a4 = "loopingisfunbutdangerous"
    b4 = "lessdangerousthancoding"
    print("Test Case 4:")
    print(f's1: "{a4}"')
    print(f's2: "{b4}"')
    print(f'Result: "{longest(a4, b4)}"') # Expected: "abcdefghilnoprstu"
    print()

    # Test Case 5
    a5 = ""
    b5 = ""
    print("Test Case 5:")
    print(f's1: "{a5}"')
    print(f's2: "{b5}"')
    print(f'Result: "{longest(a5, b5)}"') # Expected: ""
    print()