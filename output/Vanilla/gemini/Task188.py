import threading

class FooBar:
    def __init__(self, n):
        self.n = n
        self.foo_sem = threading.Semaphore(1)
        self.bar_sem = threading.Semaphore(0)

    def foo(self, printFoo):
        """
        :type printFoo: method
        :rtype: void
        """
        for _ in range(self.n):
            self.foo_sem.acquire()
            printFoo()
            self.bar_sem.release()

    def bar(self, printBar):
        """
        :type printBar: method
        :rtype: void
        """
        for _ in range(self.n):
            self.bar_sem.acquire()
            printBar()
            self.foo_sem.release()

def run_test(n):
    if n <= 0:
        return
        
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

if __name__ == "__main__":
    test_cases = [1, 2, 5, 10, 100]
    for n in test_cases:
        run_test(n)
        print() # Newline after each test case