def process(input_str: str) -> str:
    s = "" if input_str is None else input_str
    first = bytearray(s.encode('utf-8'))
    second = bytearray(len(first))
    second[:] = first

    out1 = second.decode('utf-8', errors='strict')
    print(out1)

    del first

    out2 = second.decode('utf-8', errors='strict')
    print(out2)

    del second

    return out1 + "\n" + out2 + "\n"


if __name__ == "__main__":
    tests = [
        "Hello, World!",
        "",
        "UTF-8: こんにちは",
        "Numbers: 1234567890",
        "Line1\nLine2\tTabbed!"
    ]
    for t in tests:
        out = process(t)
        print("Returned:")
        print(out, end="")