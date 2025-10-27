
import sys

def process_and_print(input_str):
    if input_str is None:
        return ""
    trimmed = input_str.rstrip()
    print(trimmed)
    return trimmed

if __name__ == "__main__":
    # Test case 1: Normal string with trailing spaces
    print("Test 1:")
    process_and_print("Hello World   ")
    
    # Test case 2: String with trailing tabs and spaces
    print("\\nTest 2:")
    process_and_print("Python Programming\\t\\t  ")
    
    # Test case 3: String with no trailing whitespace
    print("\\nTest 3:")
    process_and_print("No trailing space")
    
    # Test case 4: String with only whitespace
    print("\\nTest 4:")
    process_and_print("    ")
    
    # Test case 5: Empty string
    print("\\nTest 5:")
    process_and_print("")
    
    # Process command line arguments if provided
    if len(sys.argv) > 1:
        print("\\nCommand line argument:")
        process_and_print(sys.argv[1])
