
import time
import tempfile
import os

def binary_search(arr, target):
    left = 0
    right = len(arr) - 1
    
    while left <= right:
        mid = left + (right - left) // 2
        
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    
    return -1

def write_execution_time(execution_time):
    try:
        with tempfile.NamedTemporaryFile(mode='w', prefix='execution_time_', suffix='.txt', delete=False) as temp_file:
            temp_file.write(f"Binary Search Execution Time: {execution_time} nanoseconds\\n")
            print(f"Execution time written to: {temp_file.name}")
    except Exception as e:
        print(f"Error writing to file: {e}")

if __name__ == "__main__":
    # Test case 1
    arr1 = [1, 3, 5, 7, 9, 11, 13, 15]
    target1 = 7
    start_time1 = time.perf_counter_ns()
    result1 = binary_search(arr1, target1)
    end_time1 = time.perf_counter_ns()
    execution_time1 = end_time1 - start_time1
    print(f"Test 1: Array: {arr1}, Target: {target1}, Result: {result1}")
    write_execution_time(execution_time1)
    
    # Test case 2
    arr2 = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    target2 = 12
    start_time2 = time.perf_counter_ns()
    result2 = binary_search(arr2, target2)
    end_time2 = time.perf_counter_ns()
    execution_time2 = end_time2 - start_time2
    print(f"Test 2: Array: {arr2}, Target: {target2}, Result: {result2}")
    write_execution_time(execution_time2)
    
    # Test case 3
    arr3 = [1, 2, 3, 4, 5]
    target3 = 6
    start_time3 = time.perf_counter_ns()
    result3 = binary_search(arr3, target3)
    end_time3 = time.perf_counter_ns()
    execution_time3 = end_time3 - start_time3
    print(f"Test 3: Array: {arr3}, Target: {target3}, Result: {result3}")
    write_execution_time(execution_time3)
    
    # Test case 4
    arr4 = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    target4 = 10
    start_time4 = time.perf_counter_ns()
    result4 = binary_search(arr4, target4)
    end_time4 = time.perf_counter_ns()
    execution_time4 = end_time4 - start_time4
    print(f"Test 4: Array: {arr4}, Target: {target4}, Result: {result4}")
    write_execution_time(execution_time4)
    
    # Test case 5
    arr5 = [5, 15, 25, 35, 45, 55]
    target5 = 55
    start_time5 = time.perf_counter_ns()
    result5 = binary_search(arr5, target5)
    end_time5 = time.perf_counter_ns()
    execution_time5 = end_time5 - start_time5
    print(f"Test 5: Array: {arr5}, Target: {target5}, Result: {result5}")
    write_execution_time(execution_time5)
