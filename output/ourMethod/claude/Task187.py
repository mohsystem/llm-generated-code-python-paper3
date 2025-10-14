
from threading import Semaphore, Lock, Thread
from typing import Callable

class H2O:
    def __init__(self):
        self.h_sem = Semaphore(2)
        self.o_sem = Semaphore(1)
        self.lock = Lock()
        self.h_count = 0
        self.o_count = 0
        self.result = []

    def hydrogen(self, release_hydrogen: Callable[[], None]) -> None:
        self.h_sem.acquire()
        with self.lock:
            release_hydrogen()
            self.h_count += 1
            if self.h_count == 2 and self.o_count == 1:
                self.h_count = 0
                self.o_count = 0
                self.o_sem.release()
                self.h_sem.release(2)

    def oxygen(self, release_oxygen: Callable[[], None]) -> None:
        self.o_sem.acquire()
        with self.lock:
            release_oxygen()
            self.o_count += 1
            if self.h_count == 2 and self.o_count == 1:
                self.h_count = 0
                self.o_count = 0
                self.o_sem.release()
                self.h_sem.release(2)

    def process_water(self, water: str) -> str:
        if not water or len(water) % 3 != 0:
            return ""
        
        self.result = []
        result_lock = Lock()
        threads = []
        
        for c in water:
            if c not in ['H', 'O']:
                return ""
            
            def create_thread_func(char):
                def thread_func():
                    if char == 'H':
                        self.hydrogen(lambda: result_lock.__enter__() or self.result.append('H') or result_lock.__exit__(None, None, None))
                    else:
                        self.oxygen(lambda: result_lock.__enter__() or self.result.append('O') or result_lock.__exit__(None, None, None))
                return thread_func
            
            t = Thread(target=create_thread_func(c))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        return ''.join(self.result)


def main():
    h2o1 = H2O()
    print(f"Test 1: {h2o1.process_water('HOH')}")
    
    h2o2 = H2O()
    print(f"Test 2: {h2o2.process_water('OOHHHH')}")
    
    h2o3 = H2O()
    print(f"Test 3: {h2o3.process_water('HHHOOO')}")
    
    h2o4 = H2O()
    print(f"Test 4: {h2o4.process_water('HHO')}")
    
    h2o5 = H2O()
    print(f"Test 5: {h2o5.process_water('HHHHHHOOO')}")


if __name__ == "__main__":
    main()
