from threading import Thread, Lock
from typing import List

MAX_THREADS_CAP = 128

def run_counter(start: int, max_value: int, thread_count: int) -> int:
    threads = thread_count
    if threads < 1:
        return start
    if threads > MAX_THREADS_CAP:
        threads = MAX_THREADS_CAP

    lock = Lock()
    current = [start]  # mutable container for shared integer

    def worker(name: str) -> None:
        while True:
            with lock:
                if current[0] <= max_value:
                    current[0] += 1
                    print(f"[{name}] incremented currentCounter to {current[0]} (max {max_value})", flush=True)
                else:
                    break

    ts: List[Thread] = []
    for i in range(threads):
        name = f"Worker-{i+1}"
        t = Thread(target=worker, args=(name,), name=name, daemon=False)
        ts.append(t)
        t.start()

    for t in ts:
        t.join()

    return current[0]

if __name__ == "__main__":
    # 5 test cases
    result1 = run_counter(0, 5, 3)
    print(f"Final counter (test1): {result1}")

    result2 = run_counter(4, 4, 2)
    print(f"Final counter (test2): {result2}")

    result3 = run_counter(10, 5, 4)
    print(f"Final counter (test3): {result3}")

    result4 = run_counter(0, 50, 8)
    print(f"Final counter (test4): {result4}")

    result5 = run_counter(-2, 2, 2)
    print(f"Final counter (test5): {result5}")