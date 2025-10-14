
def longest_valid_parentheses(s):
    if not s:
        return 0
    
    max_len = 0
    dp = [0] * len(s)
    
    for i in range(1, len(s)):
        if s[i] == ')':
            if s[i - 1] == '(':
                dp[i] = (dp[i - 2] if i >= 2 else 0) + 2
            elif i - dp[i - 1] > 0 and s[i - dp[i - 1] - 1] == '(':
                dp[i] = dp[i - 1] + 2 + (dp[i - dp[i - 1] - 2] if i - dp[i - 1] >= 2 else 0)
            max_len = max(max_len, dp[i])
    
    return max_len

if __name__ == "__main__":
    # Test case 1
    print("Test 1:", longest_valid_parentheses("(()"))
    
    # Test case 2
    print("Test 2:", longest_valid_parentheses(")()())"))
    
    # Test case 3
    print("Test 3:", longest_valid_parentheses(""))
    
    # Test case 4
    print("Test 4:", longest_valid_parentheses("()(()"))
    
    # Test case 5
    print("Test 5:", longest_valid_parentheses("(()())"))
