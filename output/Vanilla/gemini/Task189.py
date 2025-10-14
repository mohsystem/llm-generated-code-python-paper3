import threading
from typing import Callable

# Python does not have a concept of a main class in the same way as Java.
# The script is executed from the top level. The main execution block
# is conventionally placed under `if __name__ == "__main__":`.

class ZeroEvenOdd:
    def __init__(self, n: int):
        self.n = n
        self.sem_zero = threading.Semaphore(1)
        self.sem_even = threading.Semaphore(0)
        self.sem_odd = threading.Semaphore(0)
        
    def zero(self, printNumber: Callable[[int], None]) -> None:
        for i in range(1, self.n + 1):
            self.sem_zero.acquire()
            printNumber(0)
            if i % 2 == 1:
                self.sem_odd.release()
            else:
                self.sem_even.release()

    def even(self, printNumber: Callable[[int], None]) -> None:
        for i in range(2, self.n + 1, 2):
            self.sem_even.acquire()
            printNumber(i)
            self.sem_zero.release()

    def odd(self, printNumber: Callable[[int], None]) -> None:
        for i in range(1, self.n + 1, 2):
            self.sem_odd.acquire()
            printNumber(i)
            self.sem_zero.release()

def run_test(n: int):
    print(f"Running test for n = {n}")
    
    def printNumber(x: int):
        print(x, end='')

    zeo = ZeroEvenOdd(n)
    
    thread_a = threading.Thread(target=zeo.zero, args=(printNumber,))
    thread_b = threading.Thread(target=zeo.even, args=(printNumber,))
    thread_c = threading.Thread(target=zeo.odd, args=(printNumber,))
    
    thread_a.start()
    thread_b.start()
    thread_c.start()
    
    thread_a.join()
    thread_b.join()
    thread_c.join()
    
    print("\n")

if __name__ == "__main__":
    test_cases = [2, 5, 1, 6, 7]
    for n in test_cases:
        run_test(n)