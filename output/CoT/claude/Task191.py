
def longest_valid_parentheses(s):
    # Input validation
    if not s or len(s) < 2:
        return 0
    
    max_len = 0
    dp = [0] * len(s)
    
    for i in range(1, len(s)):
        if s[i] == ')':
            if s[i - 1] == '(':
                # Case: ...()
                dp[i] = (dp[i - 2] if i >= 2 else 0) + 2
            elif i - dp[i - 1] > 0 and s[i - dp[i - 1] - 1] == '(':
                # Case: ...))
                dp[i] = dp[i - 1] + 2 + (dp[i - dp[i - 1] - 2] if i - dp[i - 1] >= 2 else 0)
            max_len = max(max_len, dp[i])
    
    return max_len

# Test cases
if __name__ == "__main__":
    print("Test 1:", longest_valid_parentheses("(()"), "(Expected: 2)")
    print("Test 2:", longest_valid_parentheses(")()())"), "(Expected: 4)")
    print("Test 3:", longest_valid_parentheses(""), "(Expected: 0)")
    print("Test 4:", longest_valid_parentheses("()(()"), "(Expected: 2)")
    print("Test 5:", longest_valid_parentheses("(()())"), "(Expected: 6)")
