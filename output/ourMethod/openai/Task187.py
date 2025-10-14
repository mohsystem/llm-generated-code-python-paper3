import threading
from typing import Callable, List

class H2O:
    def __init__(self) -> None:
        self.h_sem = threading.Semaphore(2)
        self.o_sem = threading.Semaphore(1)
        def barrier_action() -> None:
            # Reset permits for next molecule
            self.h_sem.release()
            self.h_sem.release()
            self.o_sem.release()
        self.barrier = threading.Barrier(3, action=barrier_action)

    def hydrogen(self, releaseHydrogen: Callable[[], None]) -> None:
        self.h_sem.acquire()
        try:
            releaseHydrogen()
            self.barrier.wait()
        finally:
            pass

    def oxygen(self, releaseOxygen: Callable[[], None]) -> None:
        self.o_sem.acquire()
        try:
            releaseOxygen()
            self.barrier.wait()
        finally:
            pass

def form_water(water: str) -> str:
    if not isinstance(water, str):
        return ""
    n = len(water)
    if n % 3 != 0:
        return ""
    h = water.count('H')
    o = water.count('O')
    if h != 2 * o or h + o != n:
        return ""

    h2o = H2O()
    out_list: List[str] = []
    out_lock = threading.Lock()

    threads: List[threading.Thread] = []
    for ch in water:
        if ch == 'H':
            t = threading.Thread(target=lambda: h2o.hydrogen(lambda: (out_lock.acquire(), out_list.append('H'), out_lock.release())))
        else:
            t = threading.Thread(target=lambda: h2o.oxygen(lambda: (out_lock.acquire(), out_list.append('O'), out_lock.release())))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return "".join(out_list)

def _validate_molecules(s: str) -> bool:
    if s is None or len(s) % 3 != 0:
        return False
    for i in range(0, len(s), 3):
        chunk = s[i:i+3]
        if chunk.count('H') != 2 or chunk.count('O') != 1:
            return False
    return True

if __name__ == "__main__":
    tests = [
        "HOH",
        "OOHHHH",
        "HHOOHH",
        "OOOHHHHHH",
        "HHOHHOHHO",
    ]
    for t in tests:
        out = form_water(t)
        print(f"Input:  {t}")
        print(f"Output: {out}")
        print(f"Valid:  {_validate_molecules(out)}")
        print("---")