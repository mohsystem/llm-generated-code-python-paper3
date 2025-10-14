BUFFER_SIZE = 16

def handle_input(s: str) -> str:
    if s is None:
        s = ""
    return s[:BUFFER_SIZE - 1]

def main():
    tests = [
        "Hello",
        "1234567890ABCDEF",
        "",
        "SafeBuffer!",
        "This is a very long string that exceeds the buffer size!",
    ]
    for idx, t in enumerate(tests, 1):
        res = handle_input(t)
        print(f"Test {idx}: {res}")

if __name__ == "__main__":
    main()