
import threading
from typing import Callable

class Task189:
    def __init__(self, n: int):
        self.n = n
        self.zero_sem = threading.Semaphore(1)
        self.even_sem = threading.Semaphore(0)
        self.odd_sem = threading.Semaphore(0)
    
    def zero(self, printNumber: Callable[[int], None]) -> None:
        for i in range(self.n):
            self.zero_sem.acquire()
            printNumber(0)
            if i % 2 == 0:
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

def test_case(n: int, expected: str):
    zero_even_odd = Task189(n)
    result = []
    lock = threading.Lock()
    
    def print_number(num: int):
        with lock:
            result.append(str(num))
    
    thread_a = threading.Thread(target=zero_even_odd.zero, args=(print_number,))
    thread_b = threading.Thread(target=zero_even_odd.even, args=(print_number,))
    thread_c = threading.Thread(target=zero_even_odd.odd, args=(print_number,))
    
    thread_a.start()
    thread_b.start()
    thread_c.start()
    
    thread_a.join()
    thread_b.join()
    thread_c.join()
    
    output = ''.join(result)
    print(f"Input: n = {n}")
    print(f"Expected: {expected}")
    print(f"Output: {output}")
    print(f"Test {'PASSED' if output == expected else 'FAILED'}")
    print()

if __name__ == "__main__":
    test_case(2, "0102")
    test_case(5, "0102030405")
    test_case(1, "01")
    test_case(3, "010203")
    test_case(4, "01020304")
