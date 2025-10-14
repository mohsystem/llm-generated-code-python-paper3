class Task141:
    @staticmethod
    def reverse_string(s: str) -> str:
        if s is None:
            return ""
        # Python handles Unicode code points; slicing is safe for most cases
        return s[::-1]


if __name__ == "__main__":
    tests = [
        "hello",
        "",
        "A",
        "racecar",
        "Hello, 世界",
    ]
    for t in tests:
        print(f'Input: "{t}" -> Reversed: "{Task141.reverse_string(t)}"')