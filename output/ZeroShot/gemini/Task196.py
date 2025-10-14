import threading
from typing import Callable

class ZeroEvenOdd:
    def __init__(self, n: int):
        self.n = n
        self.sem_zero = threading.Semaphore(1)
        self.sem_even = threading.Semaphore(0)
        self.sem_odd = threading.Semaphore(0)

    def zero(self, printNumber: Callable[[int], None]) -> None:
        """
        Prints 0 and signals the odd or even thread.
        """
        for i in range(1, self.n + 1):
            self.sem_zero.acquire()
            printNumber(0)
            if i % 2 == 1:  # Next number is odd
                self.sem_odd.release()
            else:  # Next number is even
                self.sem_even.release()

    def even(self, printNumber: Callable[[int], None]) -> None:
        """
        Prints even numbers and signals the zero thread.
        """
        for i in range(2, self.n + 1, 2):
            self.sem_even.acquire()
            printNumber(i)
            self.sem_zero.release()

    def odd(self, printNumber: Callable[[int], None]) -> None:
        """
        Prints odd numbers and signals the zero thread.
        """
        for i in range(1, self.n + 1, 2):
            self.sem_odd.acquire()
            printNumber(i)
            self.sem_zero.release()

def run_test(n: int):
    """
    Sets up and runs a single test case.
    """
    print(f"Test Case n = {n}:")
    zeo = ZeroEvenOdd(n)

    def print_number(x: int):
        print(x, end="")

    thread_a = threading.Thread(target=zeo.zero, args=(print_number,))
    thread_b = threading.Thread(target=zeo.even, args=(print_number,))
    thread_c = threading.Thread(target=zeo.odd, args=(print_number,))

    thread_a.start()
    thread_b.start()
    thread_c.start()

    thread_a.join()
    thread_b.join()
    thread_c.join()

    print("\n")

def main():
    """
    Main function to run test cases.
    """
    test_cases = [2, 5, 1, 6, 10]
    for n in test_cases:
        run_test(n)

if __name__ == "__main__":
    main()