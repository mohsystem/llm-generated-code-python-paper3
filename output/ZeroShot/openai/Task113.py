def concatenate(parts):
    if parts is None:
        return ""
    # Treat None as empty strings
    return "".join("" if s is None else str(s) for s in parts)

if __name__ == "__main__":
    # Test case 1
    t1 = ["Hello", " ", "World", "!"]
    print("Test 1:", concatenate(t1))

    # Test case 2 (Unicode)
    t2 = ["naïve", " ", "café", " ", "😊"]
    print("Test 2:", concatenate(t2))

    # Test case 3 (None entries)
    t3 = ["A", None, "B", None, "C"]
    print("Test 3:", concatenate(t3))

    # Test case 4 (empty list)
    t4 = []
    print("Test 4:", concatenate(t4))

    # Test case 5 (empty strings)
    t5 = ["", "", "x", "", "y", "", "z"]
    print("Test 5:", concatenate(t5))