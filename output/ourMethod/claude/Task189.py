
from threading import Semaphore, Thread
from typing import Callable

class ZeroEvenOdd:
    def __init__(self, n: int):
        if n < 1 or n > 1000:
            raise ValueError("n must be between 1 and 1000")
        self.n = n
        self.zero_sem = Semaphore(1)
        self.odd_sem = Semaphore(0)
        self.even_sem = Semaphore(0)
        
    def zero(self, printNumber: Callable[[int], None]) -> None:
        for i in range(1, self.n + 1):
            self.zero_sem.acquire()
            printNumber(0)
            if i % 2 == 1:
                self.odd_sem.release()
            else:
                self.even_sem.release()
    
    def even(self, printNumber: Callable[[int], None]) -> None:
        for i in range(2, self.n + 1, 2):
            self.even_sem.acquire()
            printNumber(i)
            self.zero_sem.release()
    
    def odd(self, printNumber: Callable[[int], None]) -> None:
        for i in range(1, self.n + 1, 2):
            self.odd_sem.acquire()
            printNumber(i)
            self.zero_sem.release()

def test_case(n: int, expected: str) -> None:
    result = []
    zeo = ZeroEvenOdd(n)
    
    def print_number(x: int) -> None:
        result.append(str(x))
    
    t1 = Thread(target=lambda: zeo.zero(print_number))
    t2 = Thread(target=lambda: zeo.even(print_number))
    t3 = Thread(target=lambda: zeo.odd(print_number))
    
    t1.start()
    t2.start()
    t3.start()
    
    t1.join()
    t2.join()
    t3.join()
    
    output = ''.join(result)
    print(f"Input: {n}, Output: {output}, Expected: {expected}, Pass: {output == expected}")

if __name__ == "__main__":
    test_case(2, "0102")
    test_case(5, "0102030405")
    test_case(1, "01")
    test_case(3, "010203")
    test_case(10, "01020304050607080910")
