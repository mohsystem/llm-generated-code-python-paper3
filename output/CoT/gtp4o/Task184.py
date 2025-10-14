# Chain-of-Through: 1) Problem understanding + 2) Security: unique, unpredictable names
# - Use secrets for cryptographically strong randomness
# - Maintain a registry of active names; release on reset
# - Ensure functions/methods accept inputs as parameters where applicable

import secrets
import string

class NameRegistry:
    _active = set()
    _max_attempts = 1_000_000

    @classmethod
    def _random_name(cls):
        letters = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(2))
        digits = ''.join(secrets.choice('0123456789') for _ in range(3))
        return letters + digits

    @classmethod
    def acquire_unique_name(cls):
        for _ in range(cls._max_attempts):
            candidate = cls._random_name()
            if candidate not in cls._active:
                cls._active.add(candidate)
                return candidate
        raise RuntimeError("Unable to generate a unique robot name after many attempts.")

    @classmethod
    def release_name(cls, name: str):
        if name is not None:
            cls._active.discard(name)

    @classmethod
    def is_active(cls, name: str) -> bool:
        return name in cls._active

class Robot:
    def __init__(self):
        self._name = None

    def get_name(self) -> str:
        if self._name is None:
            self._name = NameRegistry.acquire_unique_name()
        return self._name

    def reset(self) -> None:
        if self._name is not None:
            NameRegistry.release_name(self._name)
            self._name = None

def _run_tests():
    # Test 1
    r1 = Robot()
    n1 = r1.get_name()
    print(f"Test1 r1 name: {n1} active={NameRegistry.is_active(n1)}")

    # Test 2
    r2 = Robot()
    n2 = r2.get_name()
    print(f"Test2 r2 name: {n2} unique_vs_r1={n1 != n2}")

    # Test 3
    n2_again = r2.get_name()
    print(f"Test3 r2 stable: {n2} == {n2_again} -> {n2 == n2_again}")

    # Test 4
    r2.reset()
    n2_new = r2.get_name()
    print(f"Test4 r2 reset new name: {n2_new} old_different={n2 != n2_new}")

    # Test 5
    count = 1000
    robots = [Robot() for _ in range(count)]
    names = [rb.get_name() for rb in robots]
    unique = len(set(names)) == len(names)
    print(f"Test5 1000 robots unique={unique} size={len(set(names))}")

if __name__ == "__main__":
    _run_tests()