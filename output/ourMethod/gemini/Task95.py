import time
from typing import Union

def get_processor_time_in_seconds() -> float:
    """
    Gets the current processor time in seconds.
    This is the sum of the system and user CPU time of the current process.
    
    Returns:
        float: The processor time in seconds.
    """
    try:
        return time.process_time()
    except Exception as e:
        print(f"An error occurred: {e}")
        return -1.0

def consume_cpu_time() -> int:
    """A simple function to consume some CPU time."""
    total = 0
    # The range is smaller than in C/Java as Python is slower.
    for i in range(10**7):
        total += i
    return total

def main() -> None:
    """Main function with test cases."""
    print("Running 5 test cases for getting processor time:")

    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        
        start_time = get_processor_time_in_seconds()
        if start_time < 0:
            print("Could not retrieve processor time.")
            break
        print(f"Initial processor time: {start_time:.6f} seconds")
        
        # Consume some CPU time
        consume_cpu_time()
        
        end_time = get_processor_time_in_seconds()
        if end_time < 0:
            print("Could not retrieve processor time.")
            break
        print(f"Processor time after work: {end_time:.6f} seconds")
        print(f"Elapsed processor time: {end_time - start_time:.6f} seconds")

if __name__ == "__main__":
    main()