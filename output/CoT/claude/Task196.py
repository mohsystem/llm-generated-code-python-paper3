
from threading import Semaphore, Thread

class Task196:
    def __init__(self, n):
        self.n = n
        self.zero_sem = Semaphore(1)
        self.even_sem = Semaphore(0)
        self.odd_sem = Semaphore(0)
    
    def zero(self, printNumber):
        for i in range(self.n):
            self.zero_sem.acquire()
            printNumber(0)
            if i % 2 == 0:
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

def test_case(n, expected):
    zeo = Task196(n)
    result = []
    
    def printNumber(num):
        result.append(str(num))
    
    t1 = Thread(target=zeo.zero, args=(printNumber,))
    t2 = Thread(target=zeo.even, args=(printNumber,))
    t3 = Thread(target=zeo.odd, args=(printNumber,))
    
    t1.start()
    t2.start()
    t3.start()
    
    t1.join()
    t2.join()
    t3.join()
    
    output = ''.join(result)
    print(f"Test n={n}: {'PASS' if output == expected else 'FAIL'} (Expected: {expected}, Got: {output})")

if __name__ == "__main__":
    test_case(2, "0102")
    test_case(5, "0102030405")
    test_case(1, "01")
    test_case(3, "010203")
    test_case(10, "01020304050607080910")
