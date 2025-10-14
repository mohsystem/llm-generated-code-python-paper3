
import threading

class Task188:
    def __init__(self, n: int):
        self.n = n
        self.foo_lock = threading.Lock()
        self.bar_lock = threading.Lock()
        self.bar_lock.acquire()

    def foo(self, printFoo) -> None:
        for i in range(self.n):
            self.foo_lock.acquire()
            printFoo()
            self.bar_lock.release()

    def bar(self, printBar) -> None:
        for i in range(self.n):
            self.bar_lock.acquire()
            printBar()
            self.foo_lock.release()


def test_foobar(n):
    foobar = Task188(n)
    
    def print_foo():
        print("foo", end="")
    
    def print_bar():
        print("bar", end="")
    
    thread_a = threading.Thread(target=foobar.foo, args=(print_foo,))
    thread_b = threading.Thread(target=foobar.bar, args=(print_bar,))
    
    thread_a.start()
    thread_b.start()
    
    thread_a.join()
    thread_b.join()
    print()


if __name__ == "__main__":
    print("Test case 1:")
    test_foobar(1)
    
    print("\\nTest case 2:")
    test_foobar(2)
    
    print("\\nTest case 3:")
    test_foobar(5)
    
    print("\\nTest case 4:")
    test_foobar(10)
    
    print("\\nTest case 5:")
    test_foobar(3)
