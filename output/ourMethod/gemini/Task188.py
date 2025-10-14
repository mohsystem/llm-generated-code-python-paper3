import threading
from typing import Callable

class FooBar:
    def __init__(self, n: int):
        self.n = n
        self.foo_sem = threading.Semaphore(1)
        self.bar_sem = threading.Semaphore(0)

    def foo(self, printFoo: Callable[[], None]) -> None:
        for _ in range(self.n):
            self.foo_sem.acquire()
            printFoo()
            self.bar_sem.release()

    def bar(self, printBar: Callable[[], None]) -> None:
        for _ in range(self.n):
            self.bar_sem.acquire()
            printBar()
            self.foo_sem.release()

def run_test(n: int):
    print(f"Test with n = {n}:")
    foobar = FooBar(n)
    
    # Use flush=True to ensure immediate output in some environments
    print_foo = lambda: print("foo", end="", flush=True)
    print_bar = lambda: print("bar", end="", flush=True)

    thread_a = threading.Thread(target=foobar.foo, args=(print_foo,))
    thread_b = threading.Thread(target=foobar.bar, args=(print_bar,))

    thread_a.start()
    thread_b.start()

    thread_a.join()
    thread_b.join()
    
    print("\n")

if __name__ == "__main__":
    run_test(1)
    run_test(2)
    run_test(5)
    run_test(10)
    run_test(0) # Edge case