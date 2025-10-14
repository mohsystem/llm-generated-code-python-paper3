def handle_input(input_str: str, capacity: int) -> str:
    if input_str is None or capacity <= 0:
        return ""
    return input_str[:capacity]

if __name__ == "__main__":
    tests = [
        ("Hello World", 5),
        ("", 10),
        ("Short", 10),
        ("ExactSize", 9),
        ("BoundaryTest", 0),
    ]
    for i, (s, c) in enumerate(tests, 1):
        out = handle_input(s, c)
        print(f"Case {i}: [{out}]")