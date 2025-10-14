
import threading

class Task188:
    def __init__(self, n: int):
        self.n = n
        self.foo_lock = threading.Semaphore(1)
        self.bar_lock = threading.Semaphore(0)

    def foo(self, printFoo):
        for i in range(self.n):
            self.foo_lock.acquire()
            printFoo()
            self.bar_lock.release()

    def bar(self, printBar):
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
    # Test case 1: n = 1
    print("Test case 1: n = 1")
    test_foobar(1)
    
    # Test case 2: n = 2
    print("Test case 2: n = 2")
    test_foobar(2)
    
    # Test case 3: n = 5
    print("Test case 3: n = 5")
    test_foobar(5)
    
    # Test case 4: n = 10
    print("Test case 4: n = 10")
    test_foobar(10)
    
    # Test case 5: n = 3
    print("Test case 5: n = 3")
    test_foobar(3)
