def accum(s: str) -> str:
    """
    Transforms a string based on the specified accumulation rule.
    Example: accum("abcd") -> "A-Bb-Ccc-Dddd"

    :param s: The input string, containing only letters from a..z and A..Z.
    :return: The transformed string.
    """
    if not isinstance(s, str):
        return ""
    return "-".join(c.upper() + c.lower() * i for i, c in enumerate(s))

if __name__ == "__main__":
    test_cases = [
        "abcd",
        "RqaEzty",
        "cwAt",
        "Z",
        ""
    ]
    for test in test_cases:
        print(f'Input: "{test}" -> Output: "{accum(test)}"')