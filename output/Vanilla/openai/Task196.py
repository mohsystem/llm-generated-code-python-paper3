import threading

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

def printNumber(x: int):
    print(x, end='')

def run_case(n: int):
    zeo = ZeroEvenOdd(n)
    t0 = threading.Thread(target=zeo.zero, args=(printNumber,))
    t1 = threading.Thread(target=zeo.even, args=(printNumber,))
    t2 = threading.Thread(target=zeo.odd, args=(printNumber,))
    t0.start(); t1.start(); t2.start()
    t0.join(); t1.join(); t2.join()
    print()

if __name__ == "__main__":
    tests = [1, 2, 5, 7, 10]
    for n in tests:
        run_case(n)