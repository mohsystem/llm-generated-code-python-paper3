
import sys

def convert_string_to_integer(input_str):
    try:
        return int(input_str.strip())
    except ValueError:
        print(f"Error: Invalid input - cannot convert '{input_str}' to integer")
        return None

def main():
    # Test cases
    test_cases = ["123", "-456", "0", "abc", "12.34"]
    
    print("Running test cases:")
    for test_case in test_cases:
        print(f"Input: '{test_case}' -> ", end="")
        result = convert_string_to_integer(test_case)
        if result is not None:
            print(f"Output: {result}")
    
    # Command line argument processing
    if len(sys.argv) > 1:
        print("\\nCommand line argument:")
        print(f"Input: '{sys.argv[1]}' -> ", end="")
        result = convert_string_to_integer(sys.argv[1])
        if result is not None:
            print(f"Output: {result}")
    else:
        print("\\nNo command line arguments provided.")

if __name__ == "__main__":
    main()
