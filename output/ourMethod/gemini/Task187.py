import threading
from typing import Callable

class H2O:
    def __init__(self):
        self.h_sem = threading.Semaphore(2)
        self.o_sem = threading.Semaphore(1)
        # The barrier action resets the semaphores for the next molecule.
        self.barrier = threading.Barrier(3, action=self._reset_sems)

    def _reset_sems(self):
        self.h_sem.release(2)
        self.o_sem.release(1)

    def hydrogen(self, releaseHydrogen: Callable[[], None]) -> None:
        self.h_sem.acquire()
        self.barrier.wait()
        releaseHydrogen()

    def oxygen(self, releaseOxygen: Callable[[], None]) -> None:
        self.o_sem.acquire()
        self.barrier.wait()
        releaseOxygen()

def run_simulation(water: str):
    h2o = H2O()
    result = []
    lock = threading.Lock()

    def release_hydrogen():
        with lock:
            result.append('H')

    def release_oxygen():
        with lock:
            result.append('O')

    threads = []
    for atom in water:
        if atom == 'H':
            thread = threading.Thread(target=h2o.hydrogen, args=(release_hydrogen,))
            threads.append(thread)
        else: # 'O'
            thread = threading.Thread(target=h2o.oxygen, args=(release_oxygen,))
            threads.append(thread)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()
        
    print(f"Input: {water}")
    print(f"Output: {''.join(result)}")
    print()


if __name__ == "__main__":
    test_cases = ["HOH", "OOHHHH", "HHO", "HHHHHHOOO", "OHHOHH"]
    for test_case in test_cases:
        run_simulation(test_case)