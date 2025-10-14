import sys
import threading
from typing import Callable, List

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

def run_test(n: int) -> None:
    zeo = ZeroEvenOdd(n)
    out: List[str] = []
    lock = threading.Lock()

    def printNumber(x: int) -> None:
        with lock:
            out.append(str(x))
        sys.stdout.write(str(x))
        sys.stdout.flush()

    t0 = threading.Thread(target=zeo.zero, args=(printNumber,))
    t1 = threading.Thread(target=zeo.even, args=(printNumber,))
    t2 = threading.Thread(target=zeo.odd, args=(printNumber,))

    t0.start(); t1.start(); t2.start()
    t0.join(); t1.join(); t2.join()

    sys.stdout.write(" -> " + "".join(out) + "\n")
    sys.stdout.flush()

if __name__ == "__main__":
    for n in [1, 2, 3, 5, 10]:
        run_test(n)