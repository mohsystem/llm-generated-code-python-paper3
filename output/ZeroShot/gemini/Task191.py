def longest_valid_parentheses(s: str) -> int:
    """
    Given a string containing just the characters '(' and ')', returns the length of the
    longest valid (well-formed) parentheses substring.

    :param s: The input string consisting of '(' and ')'.
    :return: The length of the longest valid parentheses substring.
    """
    if not s or len(s) < 2:
        return 0

    max_length = 0
    # The stack will store indices of '(' characters.
    # We start with -1 as a sentinel value to mark the base for a valid substring.
    stack = [-1]

    for i, char in enumerate(s):
        if char == '(':
            stack.append(i)
        else:  # char == ')'
            stack.pop()
            if not stack:
                # This ')' does not have a matching '('.
                # Push its index to serve as the new base.
                stack.append(i)
            else:
                # A valid pair is found.
                # The length is the current index minus the index of the element
                # at the top of the stack (which is the new base).
                max_length = max(max_length, i - stack[-1])
    
    return max_length

if __name__ == "__main__":
    test_cases = ["(()", ")()())", "", "()(()", "((()))())"]
    expected_results = [2, 4, 0, 2, 8]

    for i, s_test in enumerate(test_cases):
        result = longest_valid_parentheses(s_test)
        print(f"Test Case {i + 1}: \"{s_test}\"")
        print(f"Result: {result}")
        print(f"Expected: {expected_results[i]}")
        print("Passed" if result == expected_results[i] else "Failed")
        print()