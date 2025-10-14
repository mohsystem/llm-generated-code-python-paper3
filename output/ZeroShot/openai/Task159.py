MAX_SIZE = 1_000_000

def allocate_buffer(size, start_val):
    if not isinstance(size, int) or size < 0 or size > MAX_SIZE:
        return None
    # Python list is dynamic, but we simulate a buffer with fixed length and initialization
    return [start_val + i for i in range(size)]

def read_at(buffer, index):
    if buffer is None or not isinstance(index, int) or index < 0 or index >= len(buffer):
        return None
    return buffer[index]

if __name__ == "__main__":
    # 5 test cases
    buf1 = allocate_buffer(10, 100)
    print("Test1:", read_at(buf1, 0) if read_at(buf1, 0) is not None else "Invalid")

    buf2 = allocate_buffer(10, 200)
    print("Test2:", read_at(buf2, 9) if read_at(buf2, 9) is not None else "Invalid")

    buf3 = allocate_buffer(10, 300)
    print("Test3:", read_at(buf3, 10) if read_at(buf3, 10) is not None else "Invalid")

    buf4 = allocate_buffer(0, 400)
    print("Test4:", read_at(buf4, 0) if read_at(buf4, 0) is not None else "Invalid")

    buf5 = allocate_buffer(5, 500)
    print("Test5:", read_at(buf5, -1) if read_at(buf5, -1) is not None else "Invalid")