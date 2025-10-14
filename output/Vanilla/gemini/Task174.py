class Task174:
    def _compute_lps_array(self, pattern: str) -> list[int]:
        """Computes the Longest Proper Prefix which is also a Suffix (LPS) array."""
        n = len(pattern)
        lps = [0] * n
        length = 0
        i = 1
        while i < n:
            if pattern[i] == pattern[length]:
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

    def shortestPalindrome(self, s: str) -> str:
        """
        Finds the shortest palindrome by adding characters in front of the given string.
        """
        if not s or len(s) <= 1:
            return s
        
        n = len(s)
        rev_s = s[::-1]
        temp = s + '#' + rev_s
        
        lps = self._compute_lps_array(temp)
        l = lps[-1]
        
        prefix = rev_s[:n - l]
        
        return prefix + s

if __name__ == '__main__':
    solution = Task174()
    
    # Test Case 1
    s1 = "aacecaaa"
    print(f"Input: {s1}")
    print(f"Output: {solution.shortestPalindrome(s1)}")
    print()

    # Test Case 2
    s2 = "abcd"
    print(f"Input: {s2}")
    print(f"Output: {solution.shortestPalindrome(s2)}")
    print()

    # Test Case 3
    s3 = "ababa"
    print(f"Input: {s3}")
    print(f"Output: {solution.shortestPalindrome(s3)}")
    print()

    # Test Case 4
    s4 = "race"
    print(f"Input: {s4}")
    print(f"Output: {solution.shortestPalindrome(s4)}")
    print()

    # Test Case 5
    s5 = "a"
    print(f"Input: {s5}")
    print(f"Output: {solution.shortestPalindrome(s5)}")
    print()