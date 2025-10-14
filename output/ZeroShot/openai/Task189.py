import threading

class ZeroEvenOdd:
    def __init__(self, n: int):
        self.n = n
        self.sem_zero = threading.Semaphore(1)
        self.sem_odd = threading.Semaphore(0)
        self.sem_even = threading.Semaphore(0)

    def zero(self, printNumber):
        for i in range(1, self.n + 1):
            self.sem_zero.acquire()
            try:
                printNumber(0)
            finally:
                if i % 2 == 1:
                    self.sem_odd.release()
                else:
                    self.sem_even.release()

    def even(self, printNumber):
        for i in range(2, self.n + 1, 2):
            self.sem_even.acquire()
            printNumber(i)
            self.sem_zero.release()

    def odd(self, printNumber):
        for i in range(1, self.n + 1, 2):
            self.sem_odd.acquire()
            printNumber(i)
            self.sem_zero.release()

def run_zero_even_odd(n: int) -> str:
    if n < 1 or n > 1000:
        return ""
    zeo = ZeroEvenOdd(n)
    out = []
    lock = threading.Lock()

    def printer(x: int):
        with lock:
            out.append(str(x))

    t0 = threading.Thread(target=zeo.zero, args=(printer,))
    t1 = threading.Thread(target=zeo.odd, args=(printer,))
    t2 = threading.Thread(target=zeo.even, args=(printer,))
    t0.start(); t1.start(); t2.start()
    t0.join(); t1.join(); t2.join()
    return "".join(out)

if __name__ == "__main__":
    tests = [1, 2, 5, 7, 10]
    for n in tests:
        print(run_zero_even_odd(n))