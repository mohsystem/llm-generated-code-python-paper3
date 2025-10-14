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

# In Python, there is no strict "main class" concept like in Java.
# The script itself is the main entry point. We will create a Task196 class
# to fulfill the requirements of the prompt.
class Task196:
    @staticmethod
    def run_test(n):
        print(f"Test case n = {n}")
        print("Output: ", end="")
        
        output = []
        def printNumber(x):
            output.append(str(x))

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
        
        print("".join(output))
        print()

    @staticmethod
    def main():
        Task196.run_test(2)
        Task196.run_test(5)
        Task196.run_test(1)
        Task196.run_test(6)
        Task196.run_test(10)

if __name__ == "__main__":
    Task196.main()