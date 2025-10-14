import threading
from typing import Callable


class FooBar:
    def __init__(self, n: int):
        self.n = n
        self._foo_sem = threading.Semaphore(1)
        self._bar_sem = threading.Semaphore(0)

    def foo(self, printFoo: Callable[[], None]) -> int:
        for _ in range(self.n):
            self._foo_sem.acquire()
            try:
                printFoo()
            finally:
                self._bar_sem.release()
        return self.n

    def bar(self, printBar: Callable[[], None]) -> int:
        for _ in range(self.n):
            self._bar_sem.acquire()
            try:
                printBar()
            finally:
                self._foo_sem.release()
        return self.n


def generate_foobar(n: int) -> str:
    if not isinstance(n, int) or n < 1 or n > 1000:
        raise ValueError("n must be an integer in [1, 1000]")

    out_parts: list[str] = []
    fb = FooBar(n)

    t1 = threading.Thread(target=lambda: fb.foo(lambda: out_parts.append("foo")))
    t2 = threading.Thread(target=lambda: fb.bar(lambda: out_parts.append("bar")))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    return "".join(out_parts)


if __name__ == "__main__":
    tests = [1, 2, 5, 10, 0]
    for n in tests:
        try:
            result = generate_foobar(n)
            print(f"n={n} -> {result}")
        except ValueError as e:
            print(f"n={n} -> error: {e}")