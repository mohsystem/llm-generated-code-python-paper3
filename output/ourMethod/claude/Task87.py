
import os
import time
import tempfile
from typing import List, Optional, Tuple


def binary_search(array: List[int], target: int) -> int:
    """Perform binary search on a sorted array."""
    if array is None:
        raise ValueError("Array cannot be None")
    
    left: int = 0
    right: int = len(array) - 1
    
    while left <= right:
        mid: int = left + (right - left) // 2
        
        if array[mid] == target:
            return mid
        elif array[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    
    return -1


def execute_and_measure(array: List[int], target: int) -> Tuple[int, float, str]:
    """Execute binary search and measure execution time."""
    if array is None:
        raise ValueError("Array cannot be None")
    
    start_time: float = time.perf_counter_ns()
    result: int = binary_search(array, target)
    end_time: float = time.perf_counter_ns()
    execution_time: float = end_time - start_time
    
    output: str = f"Target: {target}, Result: {result}, Execution time: {execution_time:.0f} nanoseconds\\n"
    
    return result, execution_time, output


def write_execution_time_to_file(content: str, base_dir: str) -> None:
    """Write execution time to a temporary file securely."""
    if content is None or base_dir is None:
        raise ValueError("Content and base_dir cannot be None")
    
    base_path: str = os.path.abspath(os.path.normpath(base_dir))
    
    if not os.path.exists(base_path) or not os.path.isdir(base_path):
        raise ValueError("Base directory does not exist or is not a directory")
    
    fd, temp_path = tempfile.mkstemp(suffix='.txt', prefix='execution_time_', dir=base_path, text=True)
    
    try:
        os.chmod(temp_path, 0o600)
        
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
            
    except Exception as e:
        try:
            os.close(fd)
        except:
            pass
        try:
            os.unlink(temp_path)
        except:
            pass
        raise e


def main() -> None:
    try:
        # Test case 1
        arr1: List[int] = [1, 3, 5, 7, 9, 11, 13, 15]
        _, _, result1 = execute_and_measure(arr1, 7)
        print(result1, end='')
        
        # Test case 2
        arr2: List[int] = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
        _, _, result2 = execute_and_measure(arr2, 14)
        print(result2, end='')
        
        # Test case 3
        arr3: List[int] = [10, 20, 30, 40, 50]
        _, _, result3 = execute_and_measure(arr3, 25)
        print(result3, end='')
        
        # Test case 4
        arr4: List[int] = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
        _, _, result4 = execute_and_measure(arr4, 5)
        print(result4, end='')
        
        # Test case 5
        arr5: List[int] = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
        _, _, result5 = execute_and_measure(arr5, 1000)
        print(result5, end='')
        
        all_results: str = result1 + result2 + result3 + result4 + result5
        
        tmp_dir: str = tempfile.gettempdir()
        write_execution_time_to_file(all_results, tmp_dir)
        
        print("Execution times written to temporary file successfully.")
        
    except Exception as e:
        print(f"Error: {e}", file=__import__('sys').stderr)


if __name__ == "__main__":
    main()
