# Chain-of-Through secure implementation: Python
# 1) Problem understanding: Integer hash set with insert, delete, search.
# 2) Security: bounded growth, safe hashing, avoid negative indices.
# 3) Secure coding: handle collisions, resize carefully, no mutable shared defaults.
# 4) Code review: verify thresholds, index computation, and resizing.
# 5) Secure output: deterministic tests.

from typing import List

class IntHashSet:
    _LOAD_FACTOR = 0.75
    _MIN_CAP = 16
    _MAX_CAP = 1 << 30

    def __init__(self) -> None:
        self._cap: int = self._MIN_CAP
        self._tab: List[list[int]] = [[] for _ in range(self._cap)]
        self._size: int = 0
        self._threshold: int = int(self._cap * self._LOAD_FACTOR)

    @staticmethod
    def _mix64(z: int) -> int:
        z &= (1 << 64) - 1
        z ^= (z >> 33)
        z = (z * 0xff51afd7ed558ccd) & ((1 << 64) - 1)
        z ^= (z >> 33)
        z = (z * 0xc4ceb9fe1a85ec53) & ((1 << 64) - 1)
        z ^= (z >> 33)
        return z & ((1 << 64) - 1)

    def _index_for(self, key: int, cap: int | None = None) -> int:
        if cap is None:
            cap = self._cap
        return self._mix64(key) & (cap - 1)

    def _resize_if_needed(self) -> None:
        if self._size <= self._threshold:
            return
        if self._cap >= self._MAX_CAP:
            return
        new_cap = self._cap << 1
        if new_cap <= 0 or new_cap > self._MAX_CAP:
            new_cap = self._MAX_CAP
        new_tab: List[list[int]] = [[] for _ in range(new_cap)]
        for bucket in self._tab:
            for key in bucket:
                idx = self._mix64(key) & (new_cap - 1)
                new_tab[idx].append(key)
        self._cap = new_cap
        self._tab = new_tab
        self._threshold = min(int(self._cap * self._LOAD_FACTOR), (1 << 31) - 1)

    def insert(self, key: int) -> bool:
        idx = self._index_for(key)
        bucket = self._tab[idx]
        for k in bucket:
            if k == key:
                return False
        bucket.append(key)
        self._size += 1
        self._resize_if_needed()
        return True

    def delete(self, key: int) -> bool:
        idx = self._index_for(key)
        bucket = self._tab[idx]
        for i, k in enumerate(bucket):
            if k == key:
                bucket.pop(i)
                self._size -= 1
                return True
        return False

    def search(self, key: int) -> bool:
        idx = self._index_for(key)
        bucket = self._tab[idx]
        for k in bucket:
            if k == key:
                return True
        return False

def _run_tests() -> None:
    s = IntHashSet()
    s.insert(10)
    s.insert(20)
    s.insert(30)
    print("T1 contains(20):", s.search(20))  # True

    print("T2 contains(15):", s.search(15))  # False

    print("T3 delete(20):", s.delete(20))    # True
    print("T3 contains(20):", s.search(20))  # False

    print("T4 insert(20):", s.insert(20))    # True
    print("T4 contains(20):", s.search(20))  # True

    print("T5 delete(99):", s.delete(99))    # False

if __name__ == "__main__":
    _run_tests()