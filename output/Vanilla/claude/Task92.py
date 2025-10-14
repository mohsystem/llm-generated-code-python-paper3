
import threading
import time

class Task92:
    def __init__(self, max_counter):
        self.current_counter = 0
        self.max_counter = max_counter
        self.lock = threading.Lock()
    
    def access_shared_resource(self, thread_name):
        if self.current_counter <= self.max_counter:
            self.lock.acquire()
            try:
                if self.current_counter <= self.max_counter:
                    self.current_counter += 1
                    print(f"{thread_name} is accessing currentCounter: {self.current_counter}")
            finally:
                self.lock.release()
    
    def get_current_counter(self):
        return self.current_counter


def main():
    # Test case 1: Basic test with 5 threads and max counter 10
    print("Test Case 1:")
    test1 = Task92(10)
    threads = []
    for i in range(1, 6):
        t = threading.Thread(target=test1.access_shared_resource, args=(f"Thread-{i}",))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    time.sleep(0.5)
    
    # Test case 2: Multiple threads with smaller max counter
    print("\\nTest Case 2:")
    test2 = Task92(3)
    threads = []
    for i in range(1, 6):
        t = threading.Thread(target=test2.access_shared_resource, args=(f"Worker-{i}",))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    time.sleep(0.5)
    
    # Test case 3: Single thread
    print("\\nTest Case 3:")
    test3 = Task92(1)
    t = threading.Thread(target=test3.access_shared_resource, args=("SingleThread",))
    t.start()
    t.join()
    
    time.sleep(0.5)
    
    # Test case 4: Max counter is 0
    print("\\nTest Case 4:")
    test4 = Task92(0)
    threads = []
    for i in range(1, 4):
        t = threading.Thread(target=test4.access_shared_resource, args=(f"Thread-{i}",))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    time.sleep(0.5)
    
    # Test case 5: Many threads with moderate max counter
    print("\\nTest Case 5:")
    test5 = Task92(7)
    threads = []
    for i in range(1, 11):
        t = threading.Thread(target=test5.access_shared_resource, args=(f"Task-{i}",))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
