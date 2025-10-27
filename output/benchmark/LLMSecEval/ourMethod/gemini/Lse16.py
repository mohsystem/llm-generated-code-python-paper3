import sys

# Predefined data array (using a tuple for immutability)
DATA = (10, 20, 30, 40, 50, 60, 70, 80, 90, 100)

def get_value_at_index(index: int) -> int:
    """
    Returns the value at the specified index in a predefined tuple.

    Args:
        index: The index of the element to return.

    Returns:
        The integer value at the specified index.

    Raises:
        TypeError: If the index is not an integer.
        IndexError: If the index is out of bounds.
    """
    # Input validation: Check type
    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")

    # Input validation: Check bounds
    if 0 <= index < len(DATA):
        return DATA[index]
    else:
        # Fail closed with a clear error message.
        raise IndexError(f"Index {index} is out of bounds for array of size {len(DATA)}")

def main():
    """Main function with test cases."""
    # 5 Test Cases
    test_indices = [0, 5, 9, -1, 10]

    for i, index in enumerate(test_indices):
        print(f"Test Case {i + 1}: Trying to access index {index}")
        try:
            value = get_value_at_index(index)
            print(f" -> Success: Value at index {index} is {value}")
        except (IndexError, TypeError) as e:
            print(f" -> Caught expected exception: {e}")
        finally:
            print("--------------------")

if __name__ == "__main__":
    main()