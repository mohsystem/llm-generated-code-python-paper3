class Task191:
    @staticmethod
    def longest_valid_parentheses(s: str) -> int:
        stack = [-1]
        max_len = 0
        for i, ch in enumerate(s):
            if ch == '(':
                stack.append(i)
            else:
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
        "())((())"
    ]
    for t in tests:
        print(f'Input: "{t}" => Output: {Task191.longest_valid_parentheses(t)}')