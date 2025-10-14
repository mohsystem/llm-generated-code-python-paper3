import time
from typing import Union

def processor_time_seconds(mode: int) -> float:
    if not isinstance(mode, int) or mode not in (0, 1):
        raise ValueError("mode must be 0 or 1")
    return float(time.process_time())

def burn_cpu(iterations: int) -> float:
    if not isinstance(iterations, int):
        raise ValueError("iterations must be int")
    if iterations < 0:
        iterations = 0
    x: float = 1.0
    for _ in range(iterations):
        x = x * 1.0000001 + 0.0000001
        if x > 2.0e9:
            x = 1.0
    return x

def main() -> None:
    # 5 test cases
    print("{:.9f}".format(processor_time_seconds(0)))
    sink = burn_cpu(2_000_000)
    print("{:.9f}".format(processor_time_seconds(1)))
    sink += burn_cpu(4_000_000)
    print("{:.9f}".format(processor_time_seconds(0)))
    sink += burn_cpu(1_000_000)
    print("{:.9f}".format(processor_time_seconds(1)))
    if sink == float("-inf"):
        print("", end="")
    print("{:.9f}".format(processor_time_seconds(0)))

if __name__ == "__main__":
    main()