def tweak_letters(s, arr):
    """
    Tweaks letters in a string based on a list of integers.

    Args:
        s: The input string (all lowercase letters).
        arr: A list of integers (0, 1, or -1) of the same length as s.

    Returns:
        The modified string.
    """
    # Assuming len(s) == len(arr) as per the prompt.
    return "".join(chr(ord(c) + t) for c, t in zip(s, arr))

if __name__ == "__main__":
    # Test Case 1
    s1, arr1 = "apple", [0, 1, -1, 0, -1]
    print(f'tweak_letters("{s1}", {arr1}) -> "{tweak_letters(s1, arr1)}"')

    # Test Case 2
    s2, arr2 = "many", [0, 0, 0, -1]
    print(f'tweak_letters("{s2}", {arr2}) -> "{tweak_letters(s2, arr2)}"')

    # Test Case 3
    s3, arr3 = "rhino", [1, 1, 1, 1, 1]
    print(f'tweak_letters("{s3}", {arr3}) -> "{tweak_letters(s3, arr3)}"')

    # Test Case 4
    s4, arr4 = "abc", [-1, 0, 1]
    print(f'tweak_letters("{s4}", {arr4}) -> "{tweak_letters(s4, arr4)}"')

    # Test Case 5
    s5, arr5 = "zulu", [1, -1, 1, -1]
    print(f'tweak_letters("{s5}", {arr5}) -> "{tweak_letters(s5, arr5)}"')