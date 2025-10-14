import threading
import sys

# A class to encapsulate the shared resource and its lock
class SharedResource:
    def __init__(self, max_counter):
        self.current_counter = 0
        self.max_counter = max_counter
        self.lock = threading.Lock()

# The function that each thread will execute
def worker(shared_resource):
    thread_name = threading.current_thread().name
    while True:
        should_break = False
        
        # The 'with' statement ensures the lock is acquired and released properly
        with shared_resource.lock:
            if shared_resource.current_counter < shared_resource.max_counter:
                shared_resource.current_counter += 1
                # Use sys.stdout.write for better flushing in some environments
                sys.stdout.write(f"{thread_name} is accessing the counter: {shared_resource.current_counter}\n")
                sys.stdout.flush()
            else:
                should_break = True
        
        if should_break:
            break

def main():
    NUM_THREADS = 5
    MAX_COUNT = 50
    
    shared_resource = SharedResource(MAX_COUNT)
    threads = []

    print(f"Starting {NUM_THREADS} threads to count up to {MAX_COUNT}")
    
    # Create and start 5 threads (test cases)
    for i in range(NUM_THREADS):
        thread = threading.Thread(target=worker, args=(shared_resource,), name=f"Thread-{i+1}")
        threads.append(thread)
        thread.start()
        
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
        
    print("All threads have finished execution.")

if __name__ == "__main__":
    main()