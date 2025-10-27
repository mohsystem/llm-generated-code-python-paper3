import sys

def secure_array_access(index_str: str):
    """
    Securely accesses an element in a predefined list based on a string index.
    It handles parsing errors and bounds checking.
    """
    data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    try:
        index = int(index_str)
        # Secure bounds checking
        if 0 <= index < len(data):
            print(f"Element at index {index}: {data[index]}")
        else:
            print(f"Error: Index {index} is out of bounds.", file=sys.stderr)
    except ValueError:
        print("Error: Invalid input. Please provide a valid integer.", file=sys.stderr)

def run_tests():
    """Runs a series of predefined test cases."""
    print("--- Running Test Cases ---")
    
    # Test Case 1: Valid index
    print('Test 1 (Input: "3"): ', end="")
    secure_array_access("3")
    
    # Test Case 2: Negative index (out of bounds)
    print('Test 2 (Input: "-1"): ', end="")
    secure_array_access("-1")

    # Test Case 3: Index equal to list size (out of bounds)
    print('Test 3 (Input: "10"): ', end="")
    secure_array_access("10")
    
    # Test Case 4: Last valid index
    print('Test 4 (Input: "9"): ', end="")
    secure_array_access("9")

    # Test Case 5: Non-numeric input
    print('Test 5 (Input: "abc"): ', end="")
    secure_array_access("abc")
    
    print("--- Test Cases Finished ---")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        # Process the command line argument
        secure_array_access(sys.argv[1])
    else:
        # Run built-in test cases if no command line argument is provided
        print("Usage: python your_script_name.py <index>")
        print("No command line argument provided. Running default test cases.")
        run_tests()