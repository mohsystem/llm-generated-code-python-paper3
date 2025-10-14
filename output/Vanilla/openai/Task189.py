import threading

# Prints number to console
def printNumber(x: int):
    print(x, end='')

class ZeroEvenOdd:
    def __init__(self, n: int):
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

def run_zero_even_odd(n: int) -> str:
    zeo = ZeroEvenOdd(n)
    out = []
    lock = threading.Lock()

    def p(x: int):
        with lock:
            out.append(str(x))
        printNumber(x)

    ta = threading.Thread(target=zeo.zero, args=(p,))
    tb = threading.Thread(target=zeo.even, args=(p,))
    tc = threading.Thread(target=zeo.odd, args=(p,))
    ta.start(); tb.start(); tc.start()
    ta.join(); tb.join(); tc.join()
    return ''.join(out)

if __name__ == "__main__":
    tests = [1, 2, 5, 6, 7]
    for n in tests:
        run_zero_even_odd(n)
        print()