import time

def get_processor_time_in_seconds():
    """
    Returns the value (in fractional seconds) of the sum of the system and
    user CPU time of the current process.
    :return: The processor time in seconds as a float.
    """
    return time.process_time()

def do_some_work():
    """A simple function to consume some CPU time."""
    total = 0
    for i in range(100_000_000):
        total += i

if __name__ == "__main__":
    print("Running 5 test cases to measure processor time...")

    # Test Case 1: Initial measurement
    print(f"Test Case 1: Start time: {get_processor_time_in_seconds():.6f} seconds")

    # Test Case 2: After some work
    do_some_work()
    print(f"Test Case 2: After first work: {get_processor_time_in_seconds():.6f} seconds")

    # Test Case 3: After more work
    do_some_work()
    print(f"Test Case 3: After second work: {get_processor_time_in_seconds():.6f} seconds")

    # Test Case 4: A measurement immediately after the previous one
    print(f"Test Case 4: Immediately after: {get_processor_time_in_seconds():.6f} seconds")
    
    # Test Case 5: After a final round of work
    do_some_work()
    print(f"Test Case 5: After final work: {get_processor_time_in_seconds():.6f} seconds")