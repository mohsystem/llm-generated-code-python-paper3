
from typing import Optional

def longest_valid_parentheses(s: Optional[str]) -> int:
    # Validate input
    if s is None:
        return 0
    
    # Validate length constraint
    if len(s) > 30000:
        raise ValueError("Input length exceeds maximum allowed")
    
    # Validate characters
    for c in s:
        if c not in ('(', ')'):
            raise ValueError("Invalid character in input")
    
    if len(s) == 0:
        return 0
    
    max_len = 0
    dp = [0] * len(s)
    
    for i in range(1, len(s)):
        if s[i] == ')':
            if s[i - 1] == '(':
                dp[i] = (dp[i - 2] if i >= 2 else 0) + 2
            elif i - dp[i - 1] > 0 and s[i - dp[i - 1] - 1] == '(':
                dp[i] = dp[i - 1] + 2 + (dp[i - dp[i - 1] - 2] if (i - dp[i - 1]) >= 2 else 0)
            max_len = max(max_len, dp[i])
    
    return max_len

if __name__ == "__main__":
    # Test case 1
    test1 = "(()"
    print(f'Input: "{test1}" => Output: {longest_valid_parentheses(test1)}')
    
    # Test case 2
    test2 = ")()())"
    print(f'Input: "{test2}" => Output: {longest_valid_parentheses(test2)}')
    
    # Test case 3
    test3 = ""
    print(f'Input: "{test3}" => Output: {longest_valid_parentheses(test3)}')
    
    # Test case 4
    test4 = "((()))"
    print(f'Input: "{test4}" => Output: {longest_valid_parentheses(test4)}')
    
    # Test case 5
    test5 = "()(())"
    print(f'Input: "{test5}" => Output: {longest_valid_parentheses(test5)}')
