import sys
import threading

class ZeroEvenOdd:
    def __init__(self, n: int):
        self.n = n
        self.zero_sem = threading.Semaphore(1)
        self.even_sem = threading.Semaphore(0)
        self.odd_sem = threading.Semaphore(0)
        self._buf = []
        self._lock = threading.Lock()

    def printNumber(self, x: int):
        sys.stdout.write(str(x))
        sys.stdout.flush()
        with self._lock:
            self._buf.append(str(x))

    def zero(self):
        for i in range(1, self.n + 1):
            self.zero_sem.acquire()
            self.printNumber(0)
            if i % 2 == 1:
                self.odd_sem.release()
            else:
                self.even_sem.release()

    def even(self):
        for i in range(2, self.n + 1, 2):
            self.even_sem.acquire()
            self.printNumber(i)
            self.zero_sem.release()

    def odd(self):
        for i in range(1, self.n + 1, 2):
            self.odd_sem.acquire()
            self.printNumber(i)
            self.zero_sem.release()

    def run(self) -> str:
        t0 = threading.Thread(target=self.zero)
        t1 = threading.Thread(target=self.even)
        t2 = threading.Thread(target=self.odd)
        t0.start(); t1.start(); t2.start()
        t0.join(); t1.join(); t2.join()
        return ''.join(self._buf)

def run_zero_even_odd(n: int) -> str:
    return ZeroEvenOdd(n).run()

if __name__ == "__main__":
    for n in [1, 2, 5, 10, 3]:
        run_zero_even_odd(n)
        print()