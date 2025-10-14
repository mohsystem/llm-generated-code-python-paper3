import time
import tempfile
import os

def binary_search(arr, target):
    """
    Performs a binary search on a sorted list.

    :param arr: The sorted list to search in.
    :param target: The value to search for.
    :return: The index of the target, or -1 if not found.
    """
    if not arr:
        return -1
    
    low = 0
    high = len(arr) - 1

    while low <= high:
        # Secure way to calculate mid to prevent potential overflow
        mid = low + (high - low) // 2
        
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
            
    return -1 # Target not found

def measure_and_write_time(arr, target):
    """
    Measures the execution time of the binary search and writes it to a temporary file.

    :param arr: The sorted list to search in.
    :param target: The value to search for.
    :return: The index of the target, or -1 if not found.
    """
    start_time = time.perf_counter_ns()
    result = binary_search(arr, target)
    end_time = time.perf_counter_ns()
    duration_ns = end_time - start_time

    try:
        # Create a secure temporary file that is deleted on close
        with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix='.txt', prefix='search_time_') as temp_file:
            log_message = f"Binary search for target {target} took {duration_ns} nanoseconds.\n"
            temp_file.write(log_message)
            temp_file.flush() # Ensure data is written to disk
            print(f"Execution time written to temporary file: {temp_file.name}")

    except (IOError, OSError) as e:
        print(f"Error writing to temporary file: {e}", file=os.sys.stderr)
    
    return result

def main():
    # The list must be sorted for binary search to work correctly.
    sorted_list = [2, 5, 8, 12, 16, 23, 38, 56, 72, 91]

    print("--- Python Test Cases ---")

    # Test Case 1: Element in the middle
    target1 = 23
    result1 = measure_and_write_time(sorted_list, target1)
    print(f"Target: {target1}, Found at index: {result1}\n")

    # Test Case 2: Element not present
    target2 = 15
    result2 = measure_and_write_time(sorted_list, target2)
    print(f"Target: {target2}, Found at index: {result2}\n")

    # Test Case 3: First element
    target3 = 2
    result3 = measure_and_write_time(sorted_list, target3)
    print(f"Target: {target3}, Found at index: {result3}\n")

    # Test Case 4: Last element
    target4 = 91
    result4 = measure_and_write_time(sorted_list, target4)
    print(f"Target: {target4}, Found at index: {result4}\n")

    # Test Case 5: Empty list
    empty_list = []
    target5 = 5
    result5 = measure_and_write_time(empty_list, target5)
    print(f"Target: {target5} (in empty list), Found at index: {result5}\n")

if __name__ == "__main__":
    main()