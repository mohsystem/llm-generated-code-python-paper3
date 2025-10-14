import threading
from typing import Callable

class ZeroEvenOdd:
    def __init__(self, n: int):
        if not (1 <= n <= 1000):
            raise ValueError("n must be in [1, 1000]")
        self.n = n
        self.zero_sem = threading.Semaphore(1)
        self.even_sem = threading.Semaphore(0)
        self.odd_sem = threading.Semaphore(0)

    def zero(self, printNumber: Callable[[int], None]) -> None:
        for i in range(1, self.n + 1):
            self.zero_sem.acquire()
            printNumber(0)
            if i % 2 == 1:
                self.odd_sem.release()
            else:
                self.even_sem.release()

    def even(self, printNumber: Callable[[int], None]) -> None:
        for i in range(2, self.n + 1, 2):
            self.even_sem.acquire()
            printNumber(i)
            self.zero_sem.release()

    def odd(self, printNumber: Callable[[int], None]) -> None:
        for i in range(1, self.n + 1, 2):
            self.odd_sem.acquire()
            printNumber(i)
            self.zero_sem.release()

def run_zero_even_odd(n: int) -> str:
    zeo = ZeroEvenOdd(n)
    buf = []
    buf_lock = threading.Lock()

    def printNumber(x: int) -> None:
        with buf_lock:
            print(x, end='')
            buf.append(str(x))

    t_zero = threading.Thread(target=zeo.zero, args=(printNumber,), name="zero-thread")
    t_even = threading.Thread(target=zeo.even, args=(printNumber,), name="even-thread")
    t_odd = threading.Thread(target=zeo.odd, args=(printNumber,), name="odd-thread")

    t_zero.start()
    t_even.start()
    t_odd.start()

    t_zero.join()
    t_even.join()
    t_odd.join()
    print()
    return ''.join(buf)

if __name__ == "__main__":
    tests = [1, 2, 5, 10, 3]
    for n in tests:
        out = run_zero_even_odd(n)
        print(f"Returned: {out}")