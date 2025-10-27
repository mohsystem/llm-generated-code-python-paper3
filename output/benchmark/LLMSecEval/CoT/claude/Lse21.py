
import sys

def process_value(input_str):
    try:
        # Validate input is not None or empty
        if input_str is None or not input_str.strip():
            print("Error: Input cannot be None or empty", file=sys.stderr)
            return -1
        
        # Parse the input safely
        value = int(input_str.strip())
        
        # Check for overflow (Python handles big integers, but we'll check reasonable bounds)
        MAX_SAFE_INT = 9223372036854775807  # sys.maxsize on 64-bit systems
        MIN_SAFE_INT = -9223372036854775808
        
        if value > MAX_SAFE_INT - 1000:
            print("Error: Integer overflow detected", file=sys.stderr)
            return -1
        
        if value < MIN_SAFE_INT + 1000:
            print("Error: Integer underflow detected", file=sys.stderr)
            return -1
        
        result = value + 1000
        print(result)
        return 0
        
    except ValueError:
        print("Error: Invalid number format", file=sys.stderr)
        return -1

def main():
    # Test cases
    test_cases = ["100", "0", "-500", "999999999", "abc"]
    
    print("Running test cases:")
    for i, test in enumerate(test_cases, 1):
        print(f"\\nTest case {i}: input = {test}")
        process_value(test)
    
    # Process command line argument if provided
    if len(sys.argv) > 1:
        print("\\nProcessing command line argument:")
        sys.exit(process_value(sys.argv[1]))

if __name__ == "__main__":
    main()
