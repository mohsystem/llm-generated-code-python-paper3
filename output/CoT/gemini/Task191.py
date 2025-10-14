def longestValidParentheses(s: str) -> int:
    """
    Given a string containing just the characters '(' and ')', returns the length of the longest 
    valid (well-formed) parentheses substring.

    This function uses a stack to keep track of the indices of the parentheses.
    A list is used as a stack, and an initial -1 is pushed to act as a base for
    calculating the length of a valid substring.

    When a '(' is encountered, its index is pushed onto the stack.
    When a ')' is encountered, the top of the stack is popped.
    - If the stack becomes empty after popping, it means the current ')' does not have a matching '('.
      So, the index of this ')' is pushed to serve as the new base for future valid substrings.
    - If the stack is not empty after popping, a valid pair is formed. The length of the
      current valid substring is the difference between the current index and the index at the top of the stack.
      The maximum length is updated accordingly.
    
    :param s: The input string containing only '(' and ')' characters.
    :return: The length of the longest valid parentheses substring.
    """
    max_len = 0
    stack = [-1]  # Base for the first valid substring

    for i, char in enumerate(s):
        if char == '(':
            stack.append(i)
        else: # char == ')'
            stack.pop()
            if not stack:
                # This ')' is unmatched, it becomes the new base
                stack.append(i)
            else:
                # A match is found. Calculate the length.
                max_len = max(max_len, i - stack[-1])
    return max_len

if __name__ == "__main__":
    # Test Case 1
    s1 = "(()"
    print(f"Input: \"{s1}\", Output: {longestValidParentheses(s1)}")

    # Test Case 2
    s2 = ")()())"
    print(f"Input: \"{s2}\", Output: {longestValidParentheses(s2)}")

    # Test Case 3
    s3 = ""
    print(f"Input: \"{s3}\", Output: {longestValidParentheses(s3)}")

    # Test Case 4
    s4 = "()(()"
    print(f"Input: \"{s4}\", Output: {longestValidParentheses(s4)}")
    
    # Test Case 5
    s5 = "((()))"
    print(f"Input: \"{s5}\", Output: {longestValidParentheses(s5)}")