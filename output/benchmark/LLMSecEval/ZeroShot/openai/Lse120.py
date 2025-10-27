def copy_and_print(data):
    if data is None:
        data = ""
    if isinstance(data, str):
        src = data.encode("utf-8")
        dst = bytearray(len(src))
        dst[:] = src
        out = dst.decode("utf-8")
        print(out)
        return out
    elif isinstance(data, (bytes, bytearray)):
        src = bytes(data)
        dst = bytearray(len(src))
        dst[:] = src
        out = bytes(dst)
        # Print bytes as UTF-8 if possible, else repr
        try:
            print(out.decode("utf-8"))
        except UnicodeDecodeError:
            print(repr(out))
        return out
    else:
        raise TypeError("Input must be str, bytes, or bytearray")

if __name__ == "__main__":
    tests = [
        "",
        "Hello, World!",
        "Secure Copy 123!@#",
        "こんにちは",
        "a" * 100,
    ]
    for t in tests:
        copy_and_print(t)