import secrets
import string
from threading import Lock

class Robot:
    _allocated = set()
    _lock = Lock()

    def __init__(self):
        self._name = None

    def get_name(self):
        if self._name is None:
            self._name = self._new_unique_name()
        return self._name

    def reset(self):
        self._name = None

    @classmethod
    def _new_unique_name(cls):
        letters = string.ascii_uppercase
        digits = string.digits
        # There are 26*26*1000 = 676000 possible names
        for _ in range(700000):
            candidate = ''.join([
                secrets.choice(letters),
                secrets.choice(letters),
                secrets.choice(digits),
                secrets.choice(digits),
                secrets.choice(digits)
            ])
            with cls._lock:
                if candidate not in cls._allocated:
                    cls._allocated.add(candidate)
                    return candidate
        raise RuntimeError("Exhausted all possible unique names")

def _run_tests():
    r1 = Robot()
    r2 = Robot()
    r3 = Robot()

    n1 = r1.get_name()
    n2 = r2.get_name()
    n3 = r3.get_name()
    print(n1)
    print(n2)
    print(n3)

    old2 = n2
    r2.reset()
    n2b = r2.get_name()
    print(n2b)

    r4 = Robot()
    r5 = Robot()
    n4 = r4.get_name()
    n5 = r5.get_name()
    print(n4)
    print(n5)

    names = {n1, n2b, n3, n4, n5}
    if len(names) != 5:
        raise AssertionError("Names are not unique")
    if n2b == old2:
        raise AssertionError("Reset did not change the name")

if __name__ == "__main__":
    _run_tests()