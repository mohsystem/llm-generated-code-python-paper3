import time
import sys

def get_processor_time_in_seconds():
  """
  Gets the current processor time in seconds.
  
  Returns:
      float: The processor time as a floating-point number of seconds.
  """
  # time.process_time() returns the sum of the system and user CPU time
  # of the current process. It is the most accurate and secure way to
  # measure processor time in Python 3.
  return time.process_time()

def consume_cpu_time():
  """A simple function to consume some CPU time."""
  sum_val = 0
  for i in range(100_000_000):
    sum_val += i

def main():
  """Main function with 5 test cases."""
  print("Running 5 test cases for processor time measurement in Python...")
  for i in range(1, 6):
    start_time = get_processor_time_in_seconds()
    print(f"Test Case {i} (start): {start_time:.6f} seconds")
    
    # Consume some CPU time to see a change
    consume_cpu_time()
    
    end_time = get_processor_time_in_seconds()
    print(f"Test Case {i} (end):   {end_time:.6f} seconds")
    print("-------------------------------------")

if __name__ == "__main__":
  main()