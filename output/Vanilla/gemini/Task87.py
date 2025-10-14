import time

def binary_search(arr, target):
    """
    Performs binary search on a sorted list.
    
    :param arr: The sorted list to search in.
    :param target: The element to search for.
    :return: The index of the target element, or -1 if not found.
    """
    left, right = 0, len(arr) - 1
    
    while left <= right:
        mid = left + (right - left) // 2
        
        if arr[mid] == target:
            return mid  # Element found
        elif arr[mid] < target:
            left = mid + 1  # Search in the right half
        else:
            right = mid - 1  # Search in the left half
            
    return -1  # Element not found

def write_execution_time(duration, target):
    """
    Writes the execution time to a temporary log file.
    
    :param duration: The execution time in nanoseconds.
    :param target: The target value that was searched for.
    """
    # Using a fixed filename for simplicity, acts as a temporary log.
    temp_file_name = "python_execution_log.tmp"
    try:
        with open(temp_file_name, "a") as f:
            f.write(f"Target: {target}, Execution Time: {duration} ns\n")
    except IOError as e:
        print(f"Error writing to temporary file: {e}")

def main():
    """ Main function with 5 test cases """
    # The list must be sorted for binary search to work.
    sorted_list = [2, 5, 8, 12, 16, 23, 38, 56, 72, 91]
    test_cases = [23, 91, 2, 15, 100]  # Targets to search for

    print("Starting Python Binary Search Test Cases...")
    print(f"List: {sorted_list}")
    
    for target in test_cases:
        print("----------------------------------------")
        start_time = time.perf_counter_ns()
        result = binary_search(sorted_list, target)
        end_time = time.perf_counter_ns()
        duration = end_time - start_time
        
        print(f"Searching for: {target}")
        if result != -1:
            print(f"Element found at index: {result}")
        else:
            print("Element not found.")
        print(f"Execution time: {duration} nanoseconds.")
        
        # Write the execution time to a temporary file
        write_execution_time(duration, target)
        
    print("----------------------------------------")
    print("All execution times have been logged to python_execution_log.tmp")

if __name__ == "__main__":
    main()