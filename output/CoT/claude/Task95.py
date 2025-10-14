
import time

def get_processor_time_in_seconds():
    return time.process_time()

def print_processor_time():
    processor_time = get_processor_time_in_seconds()
    print(f"Current processor time: {processor_time} seconds")

if __name__ == "__main__":
    print("Test Case 1:")
    print_processor_time()
    
    print("\\nTest Case 2:")
    for i in range(1000000):
        _ = i ** 0.5
    print_processor_time()
    
    print("\\nTest Case 3:")
    for i in range(5000000):
        import math
        _ = math.sin(i)
    print_processor_time()
    
    print("\\nTest Case 4:")
    time.sleep(0.1)
    print_processor_time()
    
    print("\\nTest Case 5:")
    for i in range(10000000):
        _ = str(i)
    print_processor_time()
