import threading
from typing import Callable

class Task188:
    def __init__(self, n: int):
        self.n = n
        self.foo_sem = threading.Semaphore(1)
        self.bar_sem = threading.Semaphore(0)

    def foo(self, printFoo: Callable[[], None]) -> None:
        """
        Prints "foo" n times.
        """
        for _ in range(self.n):
            self.foo_sem.acquire()
            printFoo()
            self.bar_sem.release()

    def bar(self, printBar: Callable[[], None]) -> None:
        """
        Prints "bar" n times.
        """
        for _ in range(self.n):
            self.bar_sem.acquire()
            printBar()
            self.foo_sem.release()

def run_test(n: int):
    """
    Helper function to set up and run a test case.
    """
    print(f"Running test for n = {n}")
    if n <= 0:
        print("Output: \"\"")
        print("--------------------")
        return

    foobar = Task188(n)
    
    def printFoo():
        print("foo", end='')
    
    def printBar():
        print("bar", end='')

    thread_a = threading.Thread(target=foobar.foo, args=(printFoo,))
    thread_b = threading.Thread(target=foobar.bar, args=(printBar,))
    
    print("Output: \"", end='')
    thread_a.start()
    thread_b.start()
    
    thread_a.join()
    thread_b.join()
    print("\"")
    print("--------------------")

if __name__ == "__main__":
    test_cases = [1, 2, 5, 10, 0]
    for n_val in test_cases:
        run_test(n_val)