def accum(s):
    """
    This function accumulates a string as per the problem description.
    Example: accum("abcd") -> "A-Bb-Ccc-Dddd"
    """
    if not s:
        return ""
    return '-'.join(c.upper() + c.lower() * i for i, c in enumerate(s))

if __name__ == "__main__":
    print(f'Input: "abcd" -> Output: "{accum("abcd")}"')
    print(f'Input: "RqaEzty" -> Output: "{accum("RqaEzty")}"')
    print(f'Input: "cwAt" -> Output: "{accum("cwAt")}"')
    print(f'Input: "Z" -> Output: "{accum("Z")}"')
    print(f'Input: "Mumbling" -> Output: "{accum("Mumbling")}"')