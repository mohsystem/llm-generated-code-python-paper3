import threading
from typing import List

class H2O:
    def __init__(self) -> None:
        # Fairness not guaranteed in Python's Semaphore, but grouping enforced by barrier
        self.h_sem = threading.Semaphore(2)
        self.o_sem = threading.Semaphore(1)
        self.barrier = threading.Barrier(3, action=self._reset)

    def _reset(self) -> None:
        # Replenish permits for the next molecule
        # Python's Semaphore has no bulk release; release individually.
        self.h_sem.release()
        self.h_sem.release()
        self.o_sem.release()

    def hydrogen(self, releaseHydrogen) -> None:
        try:
            self.h_sem.acquire()
            releaseHydrogen()
            self._barrier_wait_quietly()
        except Exception:
            pass

    def oxygen(self, releaseOxygen) -> None:
        try:
            self.o_sem.acquire()
            releaseOxygen()
            self._barrier_wait_quietly()
        except Exception:
            pass

    def _barrier_wait_quietly(self) -> None:
        try:
            self.barrier.wait()
        except threading.BrokenBarrierError:
            pass

def build_water(water: str) -> str:
    if water is None:
        return ""
    out: List[str] = []
    out_lock = threading.Lock()
    h2o = H2O()

    def release_h():
        with out_lock:
            out.append('H')

    def release_o():
        with out_lock:
            out.append('O')

    threads: List[threading.Thread] = []
    for i, c in enumerate(water):
        if c == 'H':
            t = threading.Thread(target=h2o.hydrogen, args=(release_h,), name=f"H-{i}")
        elif c == 'O':
            t = threading.Thread(target=h2o.oxygen, args=(release_o,), name=f"O-{i}")
        else:
            continue
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    return "".join(out)

def _is_valid_water(s: str) -> bool:
    if s is None or len(s) % 3 != 0:
        return False
    for i in range(0, len(s), 3):
        grp = s[i:i+3]
        if grp.count('H') != 2 or grp.count('O') != 1:
            return False
    return True

if __name__ == "__main__":
    tests = [
        "HOH",
        "OOHHHH",
        "HHOOHH",
        "OHOHHH",
        "HHOHHO",
    ]
    for t in tests:
        out = build_water(t)
        print(f"in={t} out={out} valid={_is_valid_water(out)}")