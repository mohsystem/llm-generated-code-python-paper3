# Chain-of-Through process:
# 1) Problem: Check if first string ends with the second.
# 2) Security: Validate types to avoid runtime issues.
# 3) Secure coding: Use str.endswith after checks.
# 4) Review: Ensure correct edge cases (empty ending).
# 5) Output: Provide final function with tests.
def solution(s, ending):
    if not isinstance(s, str) or not isinstance(ending, str):
        return False
    return s.endswith(ending)

if __name__ == "__main__":
    tests = [
        ("abc", "bc"),
        ("abc", "d"),
        ("hello", ""),
        ("", ""),
        ("abc", "abc")
    ]
    for a, b in tests:
        print(solution(a, b))