
import threading

class Task187:
    def __init__(self):
        self.hydrogen_semaphore = threading.Semaphore(2)
        self.oxygen_semaphore = threading.Semaphore(0)
        self.mutex = threading.Lock()
        self.hydrogen_count = 0

    def hydrogen(self, release_hydrogen):
        self.hydrogen_semaphore.acquire()
        
        with self.mutex:
            self.hydrogen_count += 1
            if self.hydrogen_count == 2:
                self.oxygen_semaphore.release()
        
        release_hydrogen()

    def oxygen(self, release_oxygen):
        self.oxygen_semaphore.acquire()
        
        release_oxygen()
        
        with self.mutex:
            self.hydrogen_count = 0
        
        self.hydrogen_semaphore.release()
        self.hydrogen_semaphore.release()


def main():
    test_cases = ["HOH", "OOHHHH", "HHOHHO", "HHHHHHOOO", "OHHHOH"]
    
    for water in test_cases:
        print(f"Input: {water}")
        h2o = Task187()
        result = []
        lock = threading.Lock()
        
        def release_hydrogen():
            with lock:
                result.append('H')
        
        def release_oxygen():
            with lock:
                result.append('O')
        
        threads = []
        for c in water:
            if c == 'H':
                t = threading.Thread(target=lambda: h2o.hydrogen(release_hydrogen))
            else:
                t = threading.Thread(target=lambda: h2o.oxygen(release_oxygen))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        print(f"Output: {''.join(result)}")
        print()


if __name__ == "__main__":
    main()
