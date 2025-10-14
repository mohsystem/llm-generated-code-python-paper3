
import threading

class Task92:
    def __init__(self):
        self.current_counter = 0
        self.max_counter = 10
        self.lock = threading.Lock()

    def access_shared_resource(self, thread_name):
        if self.current_counter <= self.max_counter:
            with self.lock:
                if self.current_counter <= self.max_counter:
                    self.current_counter += 1
                    print(f"{thread_name} is accessing currentCounter: {self.current_counter}")

def test_case(test_num, max_counter, num_threads, iterations):
    print(f"\\nTest Case {test_num}:")
    task = Task92()
    task.max_counter = max_counter
    
    threads = []
    for i in range(num_threads):
        thread_name = f"Thread-{i+1}"
        thread = threading.Thread(
            target=lambda name=thread_name: [task.access_shared_resource(name) for _ in range(iterations)]
        )
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    # Test case 1: 3 threads with maxCounter = 5
    test_case(1, 5, 3, 3)
    
    # Test case 2: 2 threads with maxCounter = 3
    test_case(2, 3, 2, 2)
    
    # Test case 3: 4 threads with maxCounter = 8
    test_case(3, 8, 4, 3)
    
    # Test case 4: 5 threads with maxCounter = 10
    test_case(4, 10, 5, 3)
    
    # Test case 5: 2 threads with maxCounter = 1
    test_case(5, 1, 2, 1)
