
import threading

class Task187:
    def __init__(self):
        self.hydrogen_semaphore = threading.Semaphore(2)
        self.oxygen_semaphore = threading.Semaphore(0)
        self.lock = threading.Lock()
        self.hydrogen_count = 0
    
    def hydrogen(self, releaseHydrogen):
        self.hydrogen_semaphore.acquire()
        with self.lock:
            releaseHydrogen()
            self.hydrogen_count += 1
            if self.hydrogen_count == 2:
                self.oxygen_semaphore.release()
                self.hydrogen_count = 0
    
    def oxygen(self, releaseOxygen):
        self.oxygen_semaphore.acquire()
        with self.lock:
            releaseOxygen()
            self.hydrogen_semaphore.release()
            self.hydrogen_semaphore.release()

def test_case(water):
    h2o = Task187()
    result = []
    result_lock = threading.Lock()
    
    def create_hydrogen():
        def release_hydrogen():
            with result_lock:
                result.append('H')
        h2o.hydrogen(release_hydrogen)
    
    def create_oxygen():
        def release_oxygen():
            with result_lock:
                result.append('O')
        h2o.oxygen(release_oxygen)
    
    threads = []
    for c in water:
        if c == 'H':
            thread = threading.Thread(target=create_hydrogen)
        else:
            thread = threading.Thread(target=create_oxygen)
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    print(f"Input: {water} -> Output: {''.join(result)}")

if __name__ == "__main__":
    # Test case 1
    test_case("HOH")
    
    # Test case 2
    test_case("OOHHHH")
    
    # Test case 3
    test_case("HHHHHHOOO")
    
    # Test case 4
    test_case("HHHOHHHOOO")
    
    # Test case 5
    test_case("HHOOHH")
