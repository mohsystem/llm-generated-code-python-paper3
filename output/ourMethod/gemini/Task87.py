import time
import tempfile
from typing import List

def binary_search(arr: List[int], target: int) -> int:
    """
    Performs a binary search on a sorted list of integers.

    Args:
        arr: The sorted list to search in.
        target: The value to search for.

    Returns:
        The index of the target, or -1 if not found.
    """
    low = 0
    high = len(arr) - 1

    while low <= high:
        # Use `low + (high - low) // 2` to avoid potential overflow in other languages
        mid = low + (high - low) // 2
        
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
            
    return -1  # Target not found

def main():
    """
    Main function to run test cases and write execution times to a temp file.
    """
    sorted_array = [2, 5, 8, 12, 16, 23, 38, 56, 72, 91]
    test_targets = [23, 91, 2, 15, 100]

    try:
        # Securely create a temporary file that will not be deleted on close
        # for inspection after the script runs.
        with tempfile.NamedTemporaryFile(
            mode='w', 
            delete=False, 
            suffix='.txt', 
            prefix='task87_python_times_', 
            encoding='utf-8'
        ) as tmp_file:
            temp_filename = tmp_file.name
            print(f"Execution times will be written to: {temp_filename}")
            
            for target in test_targets:
                start_time = time.perf_counter_ns()
                result = binary_search(sorted_array, target)
                end_time = time.perf_counter_ns()
                duration = end_time - start_time

                print(f"Array: {sorted_array}")
                print(f"Searching for: {target}")
                if result != -1:
                    print(f"Found at index: {result}")
                else:
                    print("Not found.")
                print(f"Execution time: {duration} nanoseconds.\n")
                
                tmp_file.write(f"Target: {target}, Time (ns): {duration}\n")
    except (IOError, OSError) as e:
        print(f"An error occurred while writing to the temporary file: {e}")

if __name__ == "__main__":
    main()