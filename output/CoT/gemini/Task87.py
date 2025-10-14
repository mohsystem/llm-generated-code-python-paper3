import time
import tempfile
import os

def binary_search(arr, target):
    """
    Performs a binary search on a sorted list.
    This implementation assumes the input list is sorted.

    :param arr: The sorted list to search in.
    :param target: The element to search for.
    :return: The index of the target element, or -1 if not found.
    """
    if not arr:
        return -1

    low = 0
    high = len(arr) - 1

    while low <= high:
        # Mitigates integer overflow in languages with fixed-size integers
        mid = low + (high - low) // 2
        
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
            
    return -1 # Target not found

def perform_search_and_log_time(arr, target):
    """
    Executes binary search, measures its execution time, and logs it to a temporary file.
    
    :param arr: The sorted list to search in.
    :param target: The element to search for.
    :return: The index of the target element, or -1 if not found.
    """
    start_time = time.perf_counter_ns()
    result = binary_search(arr, target)
    end_time = time.perf_counter_ns()
    duration = end_time - start_time

    try:
        # Securely create a named temporary file that is not deleted on close
        with tempfile.NamedTemporaryFile(mode='w', delete=False, prefix='execution_time_', suffix='.log', encoding='utf-8') as temp_f:
            temp_filename = temp_f.name
            log_message = (
                f"Binary search for target {target} on array {arr} took {duration} nanoseconds. "
                f"Result index: {result}\n"
            )
            temp_f.write(log_message)
        print(f"Execution time logged to temporary file: {temp_filename}")
    except IOError as e:
        print(f"Error writing to temporary file: {e}", file=os.sys.stderr)

    return result

if __name__ == "__main__":
    # The list must be sorted for binary search to work correctly.
    sorted_array = [2, 5, 8, 12, 16, 23, 38, 56, 72, 91]
    
    print("Running test cases...")

    # Test Case 1: Element in the middle
    target1 = 23
    print(f"Searching for {target1}... Found at index: {perform_search_and_log_time(sorted_array, target1)}\n")

    # Test Case 2: Element at the beginning
    target2 = 2
    print(f"Searching for {target2}... Found at index: {perform_search_and_log_time(sorted_array, target2)}\n")

    # Test Case 3: Element at the end
    target3 = 91
    print(f"Searching for {target3}... Found at index: {perform_search_and_log_time(sorted_array, target3)}\n")

    # Test Case 4: Element not found (smaller than all)
    target4 = 1
    print(f"Searching for {target4}... Found at index: {perform_search_and_log_time(sorted_array, target4)}\n")

    # Test Case 5: Element not found (larger than all)
    target5 = 100
    print(f"Searching for {target5}... Found at index: {perform_search_and_log_time(sorted_array, target5)}\n")