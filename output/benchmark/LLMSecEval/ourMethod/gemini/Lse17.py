import sys
from typing import List, Union

def get_value_at_index(data_list: List[int], index: int) -> int:
    """
    Returns the value at a specified index in a given list.
    This function performs bounds checking to prevent Out-of-bounds Read vulnerabilities.

    Args:
        data_list: The list to access.
        index: The index of the element to retrieve.

    Returns:
        The value at the specified index.

    Raises:
        TypeError: If data_list is not a list or index is not an integer.
        IndexError: If the index is out of the list's bounds.
    """
    # Rule #4: Ensure all input is validated.
    if not isinstance(data_list, list):
        raise TypeError("Input data must be a list.")
    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")

    # Rule #1: Ensure that access strictly adheres to the buffer's boundaries.
    if 0 <= index < len(data_list):
        return data_list[index]
    else:
        # Fail closed with a clear error for invalid index.
        raise IndexError(f"Index {index} is out of bounds for list of size {len(data_list)}")

def main() -> None:
    """Main function to run test cases."""
    # The list from which to retrieve a value.
    data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    # 5 test cases, including valid, edge, and invalid indices.
    test_indices = [0, 5, 9, -1, 10]

    print(f"Running test cases for list: {data}")
    for i, index in enumerate(test_indices):
        print(f"\n--- Test Case {i + 1}: Attempting to access index {index} ---")
        try:
            # Rule #7: Handle exceptions appropriately.
            value = get_value_at_index(data, index)
            print(f"Success: Value at index {index} is {value}")
        except (IndexError, TypeError) as e:
            # Rule #8: Provide clear, minimal error messages.
            print(f"Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()