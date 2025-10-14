import time
import math

def get_processor_time_in_seconds():
  """
  Returns the processor time for the current process in seconds.
  This is the sum of system and user CPU time.
  """
  return time.process_time()

if __name__ == "__main__":
    print("Python Processor Time Test Cases:")

    # Test Case 1: Initial time
    print(f"Test 1: {get_processor_time_in_seconds():.9f} seconds")

    # Do some work to consume CPU time
    for i in range(10000000):
        pass  # busy loop

    # Test Case 2: Time after some work
    print(f"Test 2: {get_processor_time_in_seconds():.9f} seconds")

    # Do more intensive work
    sum_val = 0
    for i in range(1, 2000000):
        sum_val += math.sqrt(i)

    # Test Case 3: Time after more work
    print(f"Test 3: {get_processor_time_in_seconds():.9f} seconds")
    
    # Test Case 4: Time immediately after, should be very similar to Test 3
    print(f"Test 4: {get_processor_time_in_seconds():.9f} seconds")

    # Do some final work
    s = ""
    for i in range(20000):
        s += "a"

    # Test Case 5: Final time
    print(f"Test 5: {get_processor_time_in_seconds():.9f} seconds")