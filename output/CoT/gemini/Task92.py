import threading
import time

class Task92:
    def __init__(self):
        self.current_counter = 0
        self.lock = threading.Lock()

    def access_resource(self, max_counter):
        while True:
            # Using 'with' statement for automatic lock acquisition and release
            with self.lock:
                if self.current_counter < max_counter:
                    self.current_counter += 1
                    print(f"Thread {threading.get_ident()} is accessing counter: {self.current_counter}")
                else:
                    # Exit the loop if the counter has reached its max
                    break
            # Small sleep to allow other threads to run, making the interleaving more visible
            time.sleep(0.01)

def run_test_case(num_threads, max_counter):
    print(f"\n--- Test Case: {num_threads} threads, max_counter {max_counter} ---")
    task = Task92()
    threads = []
    
    # Create and start threads
    for _ in range(num_threads):
        thread = threading.Thread(target=task.access_resource, args=(max_counter,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    print(f"All threads have finished. Final counter value: {task.current_counter}")

if __name__ == "__main__":
    # 5 test cases
    run_test_case(num_threads=5, max_counter=20)
    run_test_case(num_threads=3, max_counter=10)
    run_test_case(num_threads=8, max_counter=50)
    run_test_case(num_threads=2, max_counter=5)
    run_test_case(num_threads=10, max_counter=10)