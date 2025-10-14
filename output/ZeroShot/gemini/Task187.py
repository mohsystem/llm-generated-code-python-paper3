import threading
from typing import Callable

class H2O:
    def __init__(self):
        self.h_sem = threading.Semaphore(0)
        self.o_sem = threading.Semaphore(0)
        self.lock = threading.Lock()
        self.h_atoms_waiting = 0

    def hydrogen(self, releaseHydrogen: Callable[[], None]) -> None:
        with self.lock:
            self.h_atoms_waiting += 1
            if self.h_atoms_waiting >= 2:
                # A pair of H atoms is ready. Wake them up along with an O atom.
                self.h_sem.release(2)
                self.h_atoms_waiting -= 2
                self.o_sem.release(1)
        
        self.h_sem.acquire()
        releaseHydrogen()

    def oxygen(self, releaseOxygen: Callable[[], None]) -> None:
        self.o_sem.acquire()
        releaseOxygen()

def run_test(water_str: str):
    """
    Helper function to run a single test case.
    """
    print(f"Testing with input: {water_str}")
    output = []
    output_lock = threading.Lock()
    h2o = H2O()
    
    def h_task():
        h2o.hydrogen(lambda: (
            output_lock.acquire(),
            output.append('H'),
            output_lock.release()
        ))

    def o_task():
        h2o.oxygen(lambda: (
            output_lock.acquire(),
            output.append('O'),
            output_lock.release()
        ))

    threads = []
    for char in water_str:
        if char == 'H':
            threads.append(threading.Thread(target=h_task))
        else:
            threads.append(threading.Thread(target=o_task))
            
    for t in threads:
        t.start()
        
    for t in threads:
        t.join()
        
    print(f"Output: {''.join(output)}")
    print("--------------------")

if __name__ == "__main__":
    test_cases = ["HOH", "OOHHHH", "HHHHOO", "HOOHH", "HHHHHHOOO"]
    for case in test_cases:
        run_test(case)