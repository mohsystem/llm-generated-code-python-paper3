
def shortest_palindrome(s):
    if not s:
        return s
    
    # Find the longest palindrome prefix using KMP algorithm
    rev = s[::-1]
    combined = s + "#" + rev
    
    lps = compute_lps(combined)
    longest_palindrome_prefix = lps[-1]
    
    # Add the reversed suffix to the front
    suffix = s[longest_palindrome_prefix:]
    prefix_to_add = suffix[::-1]
    
    return prefix_to_add + s

def compute_lps(s):
    n = len(s)
    lps = [0] * n
    length = 0
    i = 1
    
    while i < n:
        if s[i] == s[length]:
            length += 1
            lps[i] = length
            i += 1
        else:
            if length != 0:
                length = lps[length - 1]
            else:
                lps[i] = 0
                i += 1
    
    return lps

if __name__ == "__main__":
    # Test case 1
    test1 = "aacecaaa"
    print(f"Input: {test1}")
    print(f"Output: {shortest_palindrome(test1)}")
    print()
    
    # Test case 2
    test2 = "abcd"
    print(f"Input: {test2}")
    print(f"Output: {shortest_palindrome(test2)}")
    print()
    
    # Test case 3
    test3 = ""
    print(f"Input: \"{test3}\"")
    print(f"Output: \"{shortest_palindrome(test3)}\"")
    print()
    
    # Test case 4
    test4 = "a"
    print(f"Input: {test4}")
    print(f"Output: {shortest_palindrome(test4)}")
    print()
    
    # Test case 5
    test5 = "abbacd"
    print(f"Input: {test5}")
    print(f"Output: {shortest_palindrome(test5)}")
    print()
