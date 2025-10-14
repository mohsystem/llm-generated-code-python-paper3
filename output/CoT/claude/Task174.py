
def shortest_palindrome(s):
    # Input validation
    if s is None:
        return ""
    
    if len(s) == 0:
        return ""
    
    if len(s) > 50000:
        raise ValueError("String length exceeds maximum allowed")
    
    # Validate that string contains only lowercase letters
    if not s.islower() or not s.isalpha():
        raise ValueError("String must contain only lowercase letters")
    
    # Use KMP algorithm to find longest palindromic prefix
    rev = s[::-1]
    combined = s + "#" + rev
    lps = compute_lps(combined)
    
    # Find the part to prepend
    palindrome_length = lps[-1]
    to_prepend = rev[:len(s) - palindrome_length]
    
    return to_prepend + s

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
    # Test cases
    print(shortest_palindrome("aacecaaa"))  # "aaacecaaa"
    print(shortest_palindrome("abcd"))      # "dcbabcd"
    print(shortest_palindrome(""))          # ""
    print(shortest_palindrome("a"))         # "a"
    print(shortest_palindrome("abbacd"))    # "dcabbacd"
