def shortest_palindrome(s: str) -> str:
    """
    Finds the shortest palindrome by adding characters to the front of the string.

    :param s: The input string.
    :return: The shortest palindrome.
    """
    if not s or len(s) <= 1:
        return s

    # KMP-based approach
    rev_s = s[::-1]
    temp = s + '#' + rev_s
    n = len(temp)
    lps = [0] * n

    # Compute LPS array for temp string
    length = 0
    i = 1
    while i < n:
        if temp[i] == temp[length]:
            length += 1
            lps[i] = length
            i += 1
        else:
            if length != 0:
                length = lps[length - 1]
            else:
                lps[i] = 0
                i += 1
    
    palindromic_prefix_len = lps[-1]
    
    suffix_to_prepend = s[palindromic_prefix_len:]
    prefix = suffix_to_prepend[::-1]
    
    return prefix + s

if __name__ == '__main__':
    # Test Case 1
    s1 = "aacecaaa"
    print(f'Input: "{s1}", Output: "{shortest_palindrome(s1)}"')

    # Test Case 2
    s2 = "abcd"
    print(f'Input: "{s2}", Output: "{shortest_palindrome(s2)}"')

    # Test Case 3
    s3 = "abacaba"
    print(f'Input: "{s3}", Output: "{shortest_palindrome(s3)}"')

    # Test Case 4
    s4 = ""
    print(f'Input: "{s4}", Output: "{shortest_palindrome(s4)}"')

    # Test Case 5
    s5 = "abab"
    print(f'Input: "{s5}", Output: "{shortest_palindrome(s5)}"')