def longest_valid_parentheses(s: str) -> int:
    """
    Given a string containing just the characters '(' and ')', return the length
    of the longest valid (well-formed) parentheses substring.
    """
    if not s or len(s) < 2:
        return 0

    max_len = 0
    # Stack stores indices. The first element -1 is a sentinel value
    # that acts as a boundary for the first valid substring.
    stack = [-1]

    for i, char in enumerate(s):
        if char == '(':
            stack.append(i)
        else:  # char == ')'
            stack.pop()
            if not stack:
                # This ')' is unmatched and serves as a new boundary.
                stack.append(i)
            else:
                # A valid pair is found. The length is the current index minus the
                # index of the character just before the start of this valid substring.
                max_len = max(max_len, i - stack[-1])
    
    return max_len

def main():
    test_cases = [
        ("(()", 2),
        (")()())", 4),
        ("", 0),
        ("()(()", 2),
        ("()(())", 6)
    ]

    for s, expected in test_cases:
        result = longest_valid_parentheses(s)
        print(f"Input: \"{s}\", Output: {result}")
        # In a real test suite, you would assert:
        # assert result == expected, f"Failed on {s}: expected {expected}, got {result}"

if __name__ == "__main__":
    main()