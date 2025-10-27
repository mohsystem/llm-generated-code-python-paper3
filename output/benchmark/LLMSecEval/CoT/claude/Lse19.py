
import sys

def add_thousand(input_str):
    if input_str is None or not input_str.strip():
        raise ValueError("Input cannot be None or empty")
    
    try:
        value = int(input_str.strip())
        result = value + 1000
        
        # Check for overflow (Python handles big integers automatically)
        # But we'll check against typical integer bounds for consistency
        if result > 2147483647 or result < -2147483648:
            raise OverflowError("Result exceeds integer bounds")
        
        return result
    except ValueError as e:
        raise ValueError(f"Invalid number format: {input_str}")

def main():
    # Test cases
    test_cases = ["100", "500", "-200", "0", "2147482647"]
    
    for test_case in test_cases:
        try:
            result = add_thousand(test_case)
            print(f"Input: {test_case} -> Output: {result}")
        except Exception as e:
            print(f"Input: {test_case} -> Error: {e}")
    
    # Command line argument processing
    if len(sys.argv) > 1:
        try:
            result = add_thousand(sys.argv[1])
            print(f"\\nCommand line input: {sys.argv[1]} -> Output: {result}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
