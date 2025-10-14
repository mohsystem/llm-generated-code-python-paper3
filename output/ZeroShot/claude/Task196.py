
from threading import Semaphore, Thread

class ZeroEvenOdd:
    def __init__(self, n):
        self.n = n
        self.zero_sem = Semaphore(1)
        self.even_sem = Semaphore(0)
        self.odd_sem = Semaphore(0)
        
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


def run_test(n):
    result = []
    
    def print_number(num):
        result.append(str(num))
    
    zeo = ZeroEvenOdd(n)
    
    t1 = Thread(target=zeo.zero, args=(print_number,))
    t2 = Thread(target=zeo.even, args=(print_number,))
    t3 = Thread(target=zeo.odd, args=(print_number,))
    
    t1.start()
    t2.start()
    t3.start()
    
    t1.join()
    t2.join()
    t3.join()
    
    print(f"n = {n}: {''.join(result)}")


if __name__ == "__main__":
    # Test case 1: n = 2
    run_test(2)
    
    # Test case 2: n = 5
    run_test(5)
    
    # Test case 3: n = 1
    run_test(1)
    
    # Test case 4: n = 10
    run_test(10)
    
    # Test case 5: n = 7
    run_test(7)
