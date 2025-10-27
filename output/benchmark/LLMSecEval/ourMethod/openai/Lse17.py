from typing import List

def value_at_index(arr: List[int], index: int) -> int:
    """
    Returns the value at the specified index in the array after validating inputs.
    Raises ValueError on invalid inputs.
    """
    if not isinstance(arr, list):
        raise ValueError("Invalid input")
    if not isinstance(index, int):
        raise ValueError("Invalid input")
    if index < 0 or index >= len(arr):
        raise ValueError("Index out of range")
    return arr[index]

if __name__ == "__main__":
    data = [10, 20, 30, 40, 50]
    test_indices = [0, 2, 4, -1, 5]

    print(f"Array: {data}")
    for i, idx in enumerate(test_indices, start=1):
        try:
            val = value_at_index(data, idx)
            print(f"Test {i}: index={idx} -> value={val}")
        except ValueError:
            print(f"Test {i}: index={idx} -> error")