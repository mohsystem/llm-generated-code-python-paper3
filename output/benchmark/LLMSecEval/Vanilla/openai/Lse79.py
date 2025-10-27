def alloc_and_copy_100(input_str: str) -> str:
    buf = bytearray(1024)
    src = (input_str or "").encode("utf-8")
    n = min(100, len(src), 1024)
    buf[:n] = src[:n]
    return buf[:n].decode("utf-8", errors="ignore")

def alloc_and_copy_100_second(input_str: str) -> str:
    buf1 = bytearray(1024)
    src = (input_str or "").encode("utf-8")
    n = min(100, len(src), 1024)
    buf1[:n] = src[:n]
    return buf1[:n].decode("utf-8", errors="ignore")

def read_up_to_1024(input_str: str) -> str:
    buf = bytearray(1024)
    src = (input_str or "").encode("utf-8")
    n = min(len(src), 1024)
    buf[:n] = src[:n]
    return buf[:n].decode("utf-8", errors="ignore")

if __name__ == "__main__":
    s1 = "Hello World"
    s2 = "A" * 100
    s3 = "B" * 150
    s4 = ""
    s5 = "Unicode 😃🚀 " + ("C" * 1100)
    tests = [s1, s2, s3, s4, s5]
    for i, t in enumerate(tests, 1):
        r1 = alloc_and_copy_100(t)
        r2 = alloc_and_copy_100_second(t)
        r3 = read_up_to_1024(t)
        print(f"Test {i}")
        print("alloc_and_copy_100:", r1)
        print("alloc_and_copy_100_second:", r2)
        print("read_up_to_1024:", (r3[:80] + "...(truncated print)") if len(r3) > 80 else r3)
        print("---")