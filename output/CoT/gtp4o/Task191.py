def longest_valid_parentheses(s: str) -> int:
    if s is None or len(s) == 0:
        return 0
    stack = [-1]
    max_len = 0
    for i, ch in enumerate(s):
        if ch == '(':
            stack.append(i)
        elif ch == ')':
            if stack:
                stack.pop()
            if not stack:
                stack.append(i)
            else:
                max_len = max(max_len, i - stack[-1])
    return max_len

if __name__ == "__main__":
    tests = [
        "(()",
        ")()())",
        "",
        "()(())",
        "((((("
    ]
    for t in tests:
        print(longest_valid_parentheses(t))