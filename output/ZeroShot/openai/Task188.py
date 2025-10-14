import threading

class FooBar:
    def __init__(self, n: int):
        self.n = n
        self.foo_sem = threading.Semaphore(1)
        self.bar_sem = threading.Semaphore(0)
        self.out = []

    def foo(self):
        for _ in range(self.n):
            self.foo_sem.acquire()
            try:
                self.out.append("foo")
            finally:
                self.bar_sem.release()

    def bar(self):
        for _ in range(self.n):
            self.bar_sem.acquire()
            try:
                self.out.append("bar")
            finally:
                self.foo_sem.release()

def run_foobar(n: int) -> str:
    if n < 1 or n > 1000:
        return ""
    fb = FooBar(n)
    t1 = threading.Thread(target=fb.foo, daemon=True)
    t2 = threading.Thread(target=fb.bar, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return "".join(fb.out)

if __name__ == "__main__":
    tests = [1, 2, 3, 5, 10]
    for n in tests:
        print(run_foobar(n))