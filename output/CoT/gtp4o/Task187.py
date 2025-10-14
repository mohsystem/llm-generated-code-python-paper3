import threading
from typing import Callable, List

class H2O:
    def __init__(self):
        self.h_sem = threading.Semaphore(2)
        self.o_sem = threading.Semaphore(1)
        self.barrier = threading.Barrier(3)

    def hydrogen(self, releaseHydrogen: Callable[[], None]) -> None:
        self.h_sem.acquire()
        try:
            releaseHydrogen()
            try:
                self.barrier.wait()
            except threading.BrokenBarrierError:
                pass
        finally:
            self.h_sem.release()

    def oxygen(self, releaseOxygen: Callable[[], None]) -> None:
        self.o_sem.acquire()
        try:
            releaseOxygen()
            try:
                self.barrier.wait()
            except threading.BrokenBarrierError:
                pass
        finally:
            self.o_sem.release()

def run_water(water: str) -> str:
    if water is None:
        return ""
    h2o = H2O()
    out: List[str] = []
    out_lock = threading.Lock()
    threads: List[threading.Thread] = []

    def rel_h():
        with out_lock:
            out.append('H')

    def rel_o():
        with out_lock:
            out.append('O')

    for ch in water:
        if ch == 'H':
            t = threading.Thread(target=h2o.hydrogen, args=(rel_h,))
        elif ch == 'O':
            t = threading.Thread(target=h2o.oxygen, args=(rel_o,))
        else:
            continue
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return "".join(out)

def validate_water(out: str) -> bool:
    if out is None or len(out) % 3 != 0:
        return False
    for i in range(0, len(out), 3):
        g = out[i:i+3]
        if g.count('H') != 2 or g.count('O') != 1:
            return False
    return True

if __name__ == "__main__":
    tests = [
        "HOH",
        "OOHHHH",
        "HHOHHO",
        "OHHHOH",
        "HHOOHH",
    ]
    for s in tests:
        res = run_water(s)
        print(f"Input:  {s}")
        print(f"Output: {res} | valid={validate_water(res)}")
        print("---")