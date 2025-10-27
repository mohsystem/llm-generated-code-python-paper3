def copy_and_print(s: str) -> str:
    b = s.encode('utf-8')
    chunk1 = bytearray(len(b))
    chunk1[:] = b
    chunk2 = bytearray(len(chunk1))
    for i in range(len(chunk1)):
        chunk2[i] = chunk1[i]
    out = chunk2.decode('utf-8')
    print(out)
    return out

if __name__ == "__main__":
    tests = ["Hello", "", "Memory test 123", "こんにちは", "Emoji 😀🚀"]
    for t in tests:
        r = copy_and_print(t)
        print(f"Returned: {r}")