import threading

class FooBar:
    def __init__(self, n):
        self.n = n
        self.foo_lock = threading.Semaphore(1)
        self.bar_lock = threading.Semaphore(0)

    def foo(self, printFoo: 'Callable[[], None]') -> None:
        for i in range(self.n):
            self.foo_lock.acquire()
            # printFoo() outputs "foo". Do not change or remove this line.
            printFoo()
            self.bar_lock.release()

    def bar(self, printBar: 'Callable[[], None]') -> None:
        for i in range(self.n):
            self.bar_lock.acquire()
            # printBar() outputs "bar". Do not change or remove this line.
            printBar()
            self.foo_lock.release()

def run_test(n):
    print(f"Test Case (n = {n}):")
    
    foobar = FooBar(n)
    
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
    
    print("\n")

# Main execution block with test cases
if __name__ == "__main__":
    run_test(1)
    run_test(2)
    run_test(5)
    run_test(10)
    run_test(100)