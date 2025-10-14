def longest_valid_parentheses(s: str) -> int:
    left = 0
    right = 0
    max_length = 0

    # Left to Right scan
    for char in s:
        if char == '(':
            left += 1
        else:
            right += 1
        
        if left == right:
            max_length = max(max_length, 2 * right)
        elif right > left:
            left = 0
            right = 0
            
    left = 0
    right = 0
    
    # Right to Left scan
    for i in range(len(s) - 1, -1, -1):
        char = s[i]
        if char == '(':
            left += 1
        else:
            right += 1
        
        if left == right:
            max_length = max(max_length, 2 * left)
        elif left > right:
            left = 0
            right = 0
            
    return max_length

if __name__ == '__main__':
    # Test Case 1
    s1 = "(()"
    print(f"Input: {s1}, Output: {longest_valid_parentheses(s1)}")

    # Test Case 2
    s2 = ")()())"
    print(f"Input: {s2}, Output: {longest_valid_parentheses(s2)}")

    # Test Case 3
    s3 = ""
    print(f"Input: {s3}, Output: {longest_valid_parentheses(s3)}")
    
    # Test Case 4
    s4 = "()(()"
    print(f"Input: {s4}, Output: {longest_valid_parentheses(s4)}")
    
    # Test Case 5
    s5 = "()(())"
    print(f"Input: {s5}, Output: {longest_valid_parentheses(s5)}")