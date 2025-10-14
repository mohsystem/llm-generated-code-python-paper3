from typing import List

def longest_valid_parentheses(s: str) -> int:
    if not isinstance(s, str):
        return -1
    n = len(s)
    if n < 0 or n > 30000:
        return -1
    for ch in s:
        if ch not in ('(', ')'):
            return -1
    stack: List[int] = [-1]
    max_len = 0
    for i, ch in enumerate(s):
        if ch == '(':
            stack.append(i)
        else:
            if stack:
                stack.pop()
            if not stack:
                stack.append(i)
            else:
                curr = i - stack[-1]
                if curr > max_len:
                    max_len = curr
    return max_len

if __name__ == "__main__":
    tests = [
        "(()",
        ")()())",
        "",
        "()(())",
        "abc"
    ]
    for t in tests:
        print(longest_valid_parentheses(t))