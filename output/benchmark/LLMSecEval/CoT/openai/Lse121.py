def copy_and_manage(s: str) -> bytes:
    if s is None:
        s = ""
    first = s.encode("utf-8")
    second = bytes(first)  # copy
    # Free first chunk
    first = None
    return second

if __name__ == "__main__":
    tests = ["Hello", "World!", "Memory Test", "12345", "Symbols!@#"]
    for t in tests:
        second = copy_and_manage(t)
        print(second.decode("utf-8"))
        print(second.decode("utf-8"))
        # Free second chunk
        del second