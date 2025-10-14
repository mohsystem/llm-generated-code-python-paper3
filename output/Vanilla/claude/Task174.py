
class Task174:
    @staticmethod
    def shortest_palindrome(s):
        if not s:
            return s
        
        # Find the longest palindrome prefix using KMP
        rev = s[::-1]
        combined = s + "#" + rev
        
        # Compute LPS array
        lps = Task174.compute_lps(combined)
        longest_palindrome_prefix = lps[-1]
        
        # Add the remaining suffix in reverse to the front
        suffix = s[longest_palindrome_prefix:]
        return suffix[::-1] + s
    
    @staticmethod
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
    print("Test 1:", Task174.shortest_palindrome("aacecaaa"))
    
    # Test case 2
    print("Test 2:", Task174.shortest_palindrome("abcd"))
    
    # Test case 3
    print("Test 3:", Task174.shortest_palindrome(""))
    
    # Test case 4
    print("Test 4:", Task174.shortest_palindrome("a"))
    
    # Test case 5
    print("Test 5:", Task174.shortest_palindrome("aba"))
