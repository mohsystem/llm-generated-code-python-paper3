import threading
import time

def run_counter(max_counter: int, num_threads: int) -> int:
    lock = threading.Lock()
    shared = {"current": 0, "max": max_counter}

    def worker(idx: int):
        while True:
            if shared["current"] <= shared["max"]:
                with lock:
                    if shared["current"] <= shared["max"]:
                        shared["current"] += 1
                        print(f"[Python] Thread-{idx} accessing currentCounter={shared['current']}", flush=True)
                    else:
                        break
            else:
                break
            time.sleep(0)  # yield

    threads = []
    for i in range(max(0, num_threads)):
        t = threading.Thread(target=worker, args=(i + 1,), name=f"Worker-{i+1}", daemon=False)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return shared["current"]

if __name__ == "__main__":
    tests = [
        (5, 3),
        (10, 5),
        (0, 2),
        (1, 4),
        (50, 10),
    ]
    for i, (mx, th) in enumerate(tests, 1):
        result = run_counter(mx, th)
        print(f"[Python] Test {i} final currentCounter={result} (max={mx}, threads={th})")