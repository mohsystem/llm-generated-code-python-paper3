def accum(s):
    """
    Transforms a string as per the specified examples.
    e.g., accum("abcd") -> "A-Bb-Ccc-Dddd"
    """
    if not isinstance(s, str):
        return ""
    return "-".join(c.upper() + c.lower() * i for i, c in enumerate(s))

if __name__ == '__main__':
    test_cases = ["abcd", "RqaEzty", "cwAt", "Z", ""]
    for test_case in test_cases:
        print(f'"{test_case}" -> "{accum(test_case)}"')