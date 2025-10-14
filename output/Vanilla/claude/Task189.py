
import threading
from typing import Callable

class Task189:
    def __init__(self, n: int):
        self.n = n
        self.zero_sem = threading.Semaphore(1)
        self.even_sem = threading.Semaphore(0)
        self.odd_sem = threading.Semaphore(0)
        self.current = 1

    def zero(self, printNumber: Callable[[int], None]) -> None:
        for i in range(self.n):
            self.zero_sem.acquire()
            printNumber(0)
            if self.current % 2 == 1:
                self.odd_sem.release()
            else:
                self.even_sem.release()

    def even(self, printNumber: Callable[[int], None]) -> None:
        for i in range(2, self.n + 1, 2):
            self.even_sem.acquire()
            printNumber(i)
            self.current += 1
            self.zero_sem.release()

    def odd(self, printNumber: Callable[[int], None]) -> None:
        for i in range(1, self.n + 1, 2):
            self.odd_sem.acquire()
            printNumber(i)
            self.current += 1
            self.zero_sem.release()


def test_case(n: int, expected: str):
    zeo = Task189(n)
    result = []
    
    def printNumber(x: int) -> None:
        result.append(str(x))
    
    t1 = threading.Thread(target=lambda: zeo.zero(printNumber))
    t2 = threading.Thread(target=lambda: zeo.even(printNumber))
    t3 = threading.Thread(target=lambda: zeo.odd(printNumber))
    
    t1.start()
    t2.start()
    t3.start()
    
    t1.join()
    t2.join()
    t3.join()
    
    output = ''.join(result)
    print(f"Input: n = {n}")
    print(f"Output: \"{output}\"")
    print(f"Expected: \"{expected}\"")
    print(f"Pass: {output == expected}")
    print()


if __name__ == "__main__":
    # Test case 1
    test_case(2, "0102")
    
    # Test case 2
    test_case(5, "0102030405")
    
    # Test case 3
    test_case(1, "01")
    
    # Test case 4
    test_case(3, "010203")
    
    # Test case 5
    test_case(10, "01020304050607080910")
