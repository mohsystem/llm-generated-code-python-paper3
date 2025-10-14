import threading
import sys

class SharedResource:
    def __init__(self, max_counter):
        self.current_counter = 0
        self.max_counter = max_counter
        self.lock = threading.Lock()

def worker(resource: SharedResource):
    """
    Thread function that increments a shared counter safely.
    """
    while True:
        local_value = -1
        should_break = False

        # Acquire lock to ensure atomic check-then-act operation
        with resource.lock:
            if resource.current_counter < resource.max_counter:
                resource.current_counter += 1
                local_value = resource.current_counter
            else:
                should_break = True

        if should_break:
            break
        
        if local_value != -1:
            thread_name = threading.current_thread().name
            # Use sys.stdout for thread-safe printing
            sys.stdout.write(f"Thread {thread_name} is accessing counter: {local_value}\n")

def run_test(num_threads, max_counter):
    """
    Sets up and runs a single test case.
    """
    print(f"--- Running test with {num_threads} threads and max counter {max_counter} ---")
    resource = SharedResource(max_counter)
    threads = []
    for i in range(num_threads):
        # Give each thread a name for clearer output
        t = threading.Thread(target=worker, args=(resource,), name=f"Worker-{i+1}")
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"--- Test finished. Final counter should be {max_counter} ---")
    print()

if __name__ == "__main__":
    # 5 test cases
    run_test(5, 10)
    run_test(10, 20)
    run_test(2, 50)
    run_test(20, 100)
    run_test(8, 8)