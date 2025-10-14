import threading

class Task92:
    class _SharedCounter:
        def __init__(self, start: int, max_counter: int):
            self.currentCounter = start
            self.maxCounter = max_counter
            self._lock = threading.Lock()

        def increment_if_allowed(self) -> bool:
            with self._lock:
                if self.currentCounter <= self.maxCounter:
                    self.currentCounter += 1
                    print(f"Thread {threading.current_thread().name} incremented currentCounter to {self.currentCounter}")
                    return True
                return False

    @staticmethod
    def run_counter(max_counter: int, thread_count: int) -> int:
        if thread_count <= 0:
            return 0
        shared = Task92._SharedCounter(0, max_counter)

        def worker():
            while True:
                if not shared.increment_if_allowed():
                    break

        threads = []
        for i in range(thread_count):
            t = threading.Thread(target=worker, name=f"T-{i}", daemon=False)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return shared.currentCounter

if __name__ == "__main__":
    print("Final count (max=5, threads=3):", Task92.run_counter(5, 3))
    print("Final count (max=8, threads=4):", Task92.run_counter(8, 4))
    print("Final count (max=0, threads=2):", Task92.run_counter(0, 2))
    print("Final count (max=1, threads=1):", Task92.run_counter(1, 1))
    print("Final count (max=3, threads=5):", Task92.run_counter(3, 5))