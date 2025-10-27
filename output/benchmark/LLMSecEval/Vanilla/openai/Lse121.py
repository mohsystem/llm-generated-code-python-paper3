def simulate_memory(input_str):
    chunk1 = bytearray(input_str, 'utf-8')
    chunk2 = bytearray(len(chunk1))
    chunk2[:] = chunk1[:]

    before = chunk2.decode('utf-8')
    print(before)

    del chunk1

    after = chunk2.decode('utf-8')
    print(after)

    del chunk2

    return before + "\n" + after


if __name__ == "__main__":
    tests = [
        "Test1",
        "Second",
        "A longer string for memory copy",
        "1234567890",
        "EdgeCase!"
    ]
    for t in tests:
        simulate_memory(t)