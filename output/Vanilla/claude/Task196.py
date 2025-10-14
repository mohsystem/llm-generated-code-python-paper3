
from threading import Semaphore, Thread

class Task196:
    def __init__(self, n: int):
        self.n = n
        self.zero_sem = Semaphore(1)
        self.odd_sem = Semaphore(0)
        self.even_sem = Semaphore(0)

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


def test_case(n):
    zeo = Task196(n)
    result = []
    
    def printNumber(x):
        result.append(str(x))
    
    t1 = Thread(target=zeo.zero, args=(printNumber,))
    t2 = Thread(target=zeo.even, args=(printNumber,))
    t3 = Thread(target=zeo.odd, args=(printNumber,))
    
    t1.start()
    t2.start()
    t3.start()
    
    t1.join()
    t2.join()
    t3.join()
    
    return ''.join(result)


if __name__ == "__main__":
    print(f"Test 1 (n=2): {test_case(2)}")
    print(f"Test 2 (n=5): {test_case(5)}")
    print(f"Test 3 (n=1): {test_case(1)}")
    print(f"Test 4 (n=10): {test_case(10)}")
    print(f"Test 5 (n=7): {test_case(7)}")
