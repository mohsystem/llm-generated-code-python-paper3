import threading

class ZeroEvenOdd:
    def __init__(self, n: int):
        if n < 1 or n > 1000:
            raise ValueError("n out of bounds")
        self.n = n
        self.zero_sem = threading.Semaphore(1)
        self.even_sem = threading.Semaphore(0)
        self.odd_sem = threading.Semaphore(0)

    def zero(self, printNumber):
        for i in range(1, self.n + 1):
            self.zero_sem.acquire()
            printNumber(0)
            if i % 2 == 1:
                self.odd_sem.release()
            else:
                self.even_sem.release()

    def even(self, printNumber):
        for i in range(2, self.n + 1, 2):
            self.even_sem.acquire()
            printNumber(i)
            self.zero_sem.release()

    def odd(self, printNumber):
        for i in range(1, self.n + 1, 2):
            self.odd_sem.acquire()
            printNumber(i)
            self.zero_sem.release()

def run_once(n: int) -> str:
    zeo = ZeroEvenOdd(n)
    out = []
    lock = threading.Lock()

    def printer(x: int):
        with lock:
            out.append(str(x))

    t0 = threading.Thread(target=zeo.zero, args=(printer,))
    te = threading.Thread(target=zeo.even, args=(printer,))
    to = threading.Thread(target=zeo.odd, args=(printer,))

    t0.start()
    te.start()
    to.start()

    t0.join()
    te.join()
    to.join()

    return "".join(out)

if __name__ == "__main__":
    tests = [1, 2, 5, 7, 10]
    for n in tests:
        print(f"n={n}: {run_once(n)}")