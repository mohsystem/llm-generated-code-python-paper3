import sys

def memory_copy_and_print(data):
    """
    Allocates two chunks of memory (lists in Python), copies the content of the first
    to the second, and then prints the second chunk.

    Args:
        data: A list of characters (or any iterable) to be used for the operation.
    """
    try:
        # 1. Allocate two chunks of memory. In Python, this is creating lists.
        # The first chunk is populated with the input data.
        source_chunk = list(data)

        # 2. Copy the contents of the first chunk into the second chunk.
        # The list.copy() method creates a new list with the same elements,
        # which is a safe way to copy the contents.
        destination_chunk = source_chunk.copy()

        # 3. Print the contents of the second chunk.
        print("Contents of the second chunk: ", end="")
        print("".join(destination_chunk))

    except TypeError as e:
        print(f"Error: Input data must be iterable. {e}", file=sys.stderr)


if __name__ == "__main__":
    print("--- Python Test Cases ---")
    
    # Test Case 1: Regular string
    memory_copy_and_print("Hello, Python!")
    
    # Test Case 2: String with numbers and symbols
    memory_copy_and_print("123 Test Cases!@#")
    
    # Test Case 3: Longer string
    memory_copy_and_print("This is a longer test string to check allocation.")
    
    # Test Case 4: Single character
    memory_copy_and_print("A")
    
    # Test Case 5: Empty list
    memory_copy_and_print([])