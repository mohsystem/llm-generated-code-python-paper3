import time

def get_processor_time_seconds() -> float:
    return time.process_time()

def _burn_cpu(n: int) -> int:
    s = 0
    for i in range(n):
        s += i % 7
    return s

if __name__ == "__main__":
    for i in range(1, 6):
        secs = get_processor_time_seconds()
        print(f"Run {i} - CPU time (s): {secs:.9f}")
        _ = _burn_cpu(5_000_00)