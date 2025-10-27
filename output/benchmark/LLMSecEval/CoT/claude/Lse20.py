
import sys

OFFSET = 1000

def add_offset(input_str):
    try:
        value = int(input_str)
        # Check for potential integer overflow (Python handles big integers, but we validate range)
        result = value + OFFSET
        if result > sys.maxsize or result < -sys.maxsize - 1:
            raise OverflowError("Integer overflow detected")
        return result
    except ValueError:
        raise ValueError("Invalid input: not a valid integer")

def main():
    # Test cases
    test_cases = ["100", "0", "-500", "2147482647", "50"]
    
    for test_case in test_cases:
        try:
            result = add_offset(test_case)
            print(f"Input: {test_case} -> Output: {result}")
        except Exception as e:
            print(f"Input: {test_case} -> Error: {e}")

if __name__ == "__main__":
    main()
