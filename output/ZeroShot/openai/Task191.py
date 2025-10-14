def longestValidParentheses(s: str) -> int:
    if s is None or len(s) == 0:
        return 0
    stack = [-1]
    max_len = 0
    for i, c in enumerate(s):
        if c == '(':
            stack.append(i)
        elif c == ')':
            if stack:
                stack.pop()
            if not stack:
                stack.append(i)
            else:
                current_len = i - stack[-1]
                if current_len > max_len:
                    max_len = current_len
        else:
            # Ignore any unexpected characters for safety
            continue
    return max_len


if __name__ == "__main__":
    tests = [
        "(()",
        ")()())",
        "",
        "()(())",
        "())((())"
    ]
    for t in tests:
        print(f'Input: "{t}" -> {longestValidParentheses(t)}')