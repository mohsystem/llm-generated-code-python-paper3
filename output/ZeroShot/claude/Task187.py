
import threading

class Task187:
    def __init__(self):
        self.hydrogen_sem = threading.Semaphore(2)
        self.oxygen_sem = threading.Semaphore(0)
        self.lock = threading.Lock()
        self.hydrogen_count = 0
        self.result = []

    def hydrogen(self, release_hydrogen):
        self.hydrogen_sem.acquire()
        with self.lock:
            release_hydrogen()
            self.hydrogen_count += 1
            if self.hydrogen_count == 2:
                self.oxygen_sem.release()

    def oxygen(self, release_oxygen):
        self.oxygen_sem.acquire()
        with self.lock:
            release_oxygen()
            self.hydrogen_count = 0
            self.hydrogen_sem.release()
            self.hydrogen_sem.release()

    def build_water(self, water):
        self.result = []
        threads = []
        
        for c in water:
            if c == 'H':
                t = threading.Thread(target=self.hydrogen, args=(lambda: self.result.append('H'),))
            else:
                t = threading.Thread(target=self.oxygen, args=(lambda: self.result.append('O'),))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        return ''.join(self.result)


if __name__ == "__main__":
    test_cases = ["HOH", "OOHHHH", "HHOHHO", "HHHHHHOOO", "OHHHOH"]
    
    for test_case in test_cases:
        h2o = Task187()
        output = h2o.build_water(test_case)
        print(f"Input: {test_case} -> Output: {output}")
