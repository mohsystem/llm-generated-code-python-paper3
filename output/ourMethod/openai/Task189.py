import threading
from typing import Callable, List

class ZeroEvenOdd:
    def __init__(self, n: int) -> None:
        if not (1 <= n <= 1000):
            raise ValueError("n out of range")
        self.n = n
        self._zero_sem = threading.Semaphore(1)
        self._even_sem = threading.Semaphore(0)
        self._odd_sem = threading.Semaphore(0)

    def zero(self, printNumber: Callable[[int], None]) -> None:
        for i in range(1, self.n + 1):
            self._zero_sem.acquire()
            printNumber(0)
            if i % 2 == 1:
                self._odd_sem.release()
            else:
                self._even_sem.release()

    def even(self, printNumber: Callable[[int], None]) -> None:
        for i in range(2, self.n + 1, 2):
            self._even_sem.acquire()
            printNumber(i)
            self._zero_sem.release()

    def odd(self, printNumber: Callable[[int], None]) -> None:
        for i in range(1, self.n + 1, 2):
            self._odd_sem.acquire()
            printNumber(i)
            self._zero_sem.release()

def printNumber(x: int) -> None:
    print(x, end='')

def run_test(n: int) -> None:
    zeo = ZeroEvenOdd(n)
    t0 = threading.Thread(target=zeo.zero, args=(printNumber,))
    t1 = threading.Thread(target=zeo.even, args=(printNumber,))
    t2 = threading.Thread(target=zeo.odd, args=(printNumber,))
    t0.start(); t1.start(); t2.start()
    t0.join(); t1.join(); t2.join()
    print()

def main() -> None:
    tests: List[int] = [1, 2, 5, 7, 10]
    for n in tests:
        run_test(n)

if __name__ == "__main__":
    main()