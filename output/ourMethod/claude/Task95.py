
import time
from typing import Union

def get_processor_time_in_seconds() -> float:
    """Returns the current processor time in seconds."""
    cpu_time = time.process_time()
    if not isinstance(cpu_time, (int, float)) or cpu_time < 0:
        raise ValueError("Invalid CPU time value")
    return float(cpu_time)

def main() -> None:
    try:
        # Test case 1: Basic call
        time1 = get_processor_time_in_seconds()
        print(f"Test 1 - Processor time: {time1} seconds")

        # Test case 2: After some computation
        total = sum(range(1000000))
        time2 = get_processor_time_in_seconds()
        print(f"Test 2 - Processor time after computation: {time2} seconds")

        # Test case 3: Multiple calls
        time3 = get_processor_time_in_seconds()
        print(f"Test 3 - Processor time: {time3} seconds")

        # Test case 4: After sleep (CPU time should not increase much)
        time.sleep(0.01)
        time4 = get_processor_time_in_seconds()
        print(f"Test 4 - Processor time after sleep: {time4} seconds")

        # Test case 5: Final measurement
        time5 = get_processor_time_in_seconds()
        print(f"Test 5 - Processor time: {time5} seconds")

    except (ValueError, OSError) as e:
        print(f"Error: {e}", file=__import__('sys').stderr)

if __name__ == "__main__":
    main()
