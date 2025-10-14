
import time

def get_current_processor_time():
    return time.perf_counter()

if __name__ == "__main__":
    # Test case 1
    print("Test case 1:")
    time1 = get_current_processor_time()
    print(f"Current processor time: {time1} seconds")
    
    # Test case 2
    print("\\nTest case 2:")
    time2 = get_current_processor_time()
    print(f"Current processor time: {time2} seconds")
    
    # Test case 3 - with some delay
    print("\\nTest case 3 (after 1 second delay):")
    time.sleep(1)
    time3 = get_current_processor_time()
    print(f"Current processor time: {time3} seconds")
    
    # Test case 4
    print("\\nTest case 4:")
    time4 = get_current_processor_time()
    print(f"Current processor time: {time4} seconds")
    print(f"Time difference from test 3: {time4 - time3} seconds")
    
    # Test case 5 - with computation
    print("\\nTest case 5 (after computation):")
    start_time = get_current_processor_time()
    total = sum(range(10000000))
    end_time = get_current_processor_time()
    print(f"Start time: {start_time} seconds")
    print(f"End time: {end_time} seconds")
    print(f"Elapsed time: {end_time - start_time} seconds")
