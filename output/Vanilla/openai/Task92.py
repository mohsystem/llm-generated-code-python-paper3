import threading

def run_counter(max_counter: int, num_threads: int) -> int:
    current = [0]
    lock = threading.Lock()

    def worker():
        while True:
            with lock:
                if current[0] <= max_counter:
                    current[0] += 1
                    print(f"Python Thread {threading.current_thread().name} incremented currentCounter to {current[0]}")
                else:
                    return

    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker, name=f"T-{i+1}")
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return current[0]

if __name__ == "__main__":
    print("Python Final:", run_counter(5, 3))
    print("Python Final:", run_counter(0, 2))
    print("Python Final:", run_counter(10, 5))
    print("Python Final:", run_counter(3, 10))
    print("Python Final:", run_counter(15, 4))