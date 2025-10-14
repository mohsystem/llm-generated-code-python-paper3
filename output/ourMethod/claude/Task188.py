
import threading
from typing import Callable

class FooBar:
    def __init__(self, n: int):
        if not isinstance(n, int) or n < 1 or n > 1000:
            raise ValueError("n must be an integer between 1 and 1000")
        self.n = n
        self.foo_sem = threading.Semaphore(1)
        self.bar_sem = threading.Semaphore(0)

    def foo(self, printFoo: Callable[[], None]) -> None:
        for i in range(self.n):
            self.foo_sem.acquire()
            printFoo()
            self.bar_sem.release()

    def bar(self, printBar: Callable[[], None]) -> None:
        for i in range(self.n):
            self.bar_sem.acquire()
            printBar()
            self.foo_sem.release()


def main():
    test_cases = [1, 2, 3, 5, 10]
    
    for n in test_cases:
        print(f"n={n}: ", end="")
        foo_bar = FooBar(n)
        result = []
        
        def print_foo():
            result.append("foo")
        
        def print_bar():
            result.append("bar")
        
        t1 = threading.Thread(target=foo_bar.foo, args=(print_foo,))
        t2 = threading.Thread(target=foo_bar.bar, args=(print_bar,))
        
        t1.start()
        t2.start()
        
        t1.join()
        t2.join()
        
        print("".join(result))


if __name__ == "__main__":
    main()
