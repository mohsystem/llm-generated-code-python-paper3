def reverse_string(s: str) -> str:
    return s[::-1]

if __name__ == "__main__":
    tests = ["", "a", "abcde", "Hello, World!", "12345 racecar"]
    for t in tests:
        print(reverse_string(t))