import threading
from typing import Callable

class ZeroEvenOdd:
    def __init__(self, n):
        self.n = n
        self.zero_sem = threading.Semaphore(1)
        self.even_sem = threading.Semaphore(0)
        self.odd_sem = threading.Semaphore(0)

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

def print_number_func(x: int) -> None:
    print(x, end='')

def run_test(n: int):
    print(f"Test Case n = {n}: ", end='')
    zeo = ZeroEvenOdd(n)
    
    thread_a = threading.Thread(target=zeo.zero, args=(print_number_func,))
    thread_b = threading.Thread(target=zeo.even, args=(print_number_func,))
    thread_c = threading.Thread(target=zeo.odd, args=(print_number_func,))
    
    thread_a.start()
    thread_b.start()
    thread_c.start()
    
    thread_a.join()
    thread_b.join()
    thread_c.join()
    
    print("\n")

if __name__ == "__main__":
    test_cases = [1, 2, 5, 6, 10]
    for n_val in test_cases:
        run_test(n_val)