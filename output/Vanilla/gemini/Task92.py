import threading

# Shared resources accessible by all threads
current_counter = 0
max_counter = 0
lock = threading.Lock()

def increment_counter():
    """
    The target function for each thread. It increments the shared counter
    in a thread-safe manner until it reaches the max_counter.
    """
    global current_counter
    while True:
        # Acquire lock using a context manager for safety (ensures release)
        with lock:
            # Check if the counter is less than the max value
            if current_counter < max_counter:
                current_counter += 1
                print(f"{threading.current_thread().name} is accessing counter: {current_counter}", flush=True)
            else:
                # Max count reached, exit the loop
                break
        # The lock is released automatically upon exiting the 'with' block

def run_simulation(num_threads, max_val):
    """
    Sets up and runs a single simulation with a given number of threads and a max counter value.
    """
    global current_counter, max_counter
    print(f"--- Starting Test: {num_threads} threads, max_counter = {max_val} ---")

    # Reset shared state for the test
    current_counter = 0
    max_counter = max_val

    threads = []
    for i in range(num_threads):
        # Create and start each thread
        thread = threading.Thread(target=increment_counter, name=f"Thread-{i+1}")
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete their execution
    for thread in threads:
        thread.join()

    print(f"--- Test Finished. Final counter value: {current_counter} ---\n")

def main():
    """
    Main function to run the 5 test cases.
    """
    run_simulation(2, 10)
    run_simulation(5, 20)
    run_simulation(10, 100)
    run_simulation(3, 5)
    run_simulation(8, 50)

if __name__ == "__main__":
    main()