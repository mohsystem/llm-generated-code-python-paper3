
import time

def get_current_processor_time():
    return time.perf_counter()

def main():
    # Test case 1
    print("Test case 1:")
    time1 = get_current_processor_time()
    print(f"Current processor time: {time1} seconds")
    
    # Test case 2
    print("\\nTest case 2:")
    time2 = get_current_processor_time()
    print(f"Current processor time: {time2} seconds")
    
    # Test case 3 - with some delay
    print("\\nTest case 3 (after small delay):")
    time.sleep(0.1)
    time3 = get_current_processor_time()
    print(f"Current processor time: {time3} seconds")
    
    # Test case 4
    print("\\nTest case 4:")
    time4 = get_current_processor_time()
    print(f"Current processor time: {time4} seconds")
    print(f"Time elapsed since test case 1: {time4 - time1} seconds")
    
    # Test case 5
    print("\\nTest case 5:")
    time5 = get_current_processor_time()
    print(f"Current processor time: {time5} seconds")
    print(f"Time elapsed since test case 4: {time5 - time4} seconds")

if __name__ == "__main__":
    main()
