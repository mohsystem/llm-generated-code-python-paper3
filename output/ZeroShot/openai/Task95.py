import time

def get_processor_time_seconds() -> float:
    # Returns CPU time in seconds for the current process.
    return float(time.process_time())

def do_cpu_work(n: int) -> int:
    if n <= 0:
        return 0
    s = 0
    for i in range(n):
        s += (i ^ (i << 1)) & 0xFFFFFFFF
    return s

if __name__ == "__main__":
    # 5 test cases
    for i in range(1, 6):
        _ = do_cpu_work(200_000 * i)
        secs = get_processor_time_seconds()
        print(f"Test {i}: {secs:.6f} seconds")