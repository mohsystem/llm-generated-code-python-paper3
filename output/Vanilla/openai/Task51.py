def encrypt(s: str) -> str:
    result = []
    for ch in s:
        if 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + 3) % 26 + ord('A')))
        elif 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + 3) % 26 + ord('a')))
        elif '0' <= ch <= '9':
            result.append(chr((ord(ch) - ord('0') + 5) % 10 + ord('0')))
        else:
            result.append(ch)
    return ''.join(result)

if __name__ == "__main__":
    tests = [
        "Hello, World!",
        "xyz XYZ",
        "Encrypt123",
        "",
        "Attack at dawn! 09"
    ]
    for t in tests:
        print("Input: ", t)
        print("Output:", encrypt(t))
        print()