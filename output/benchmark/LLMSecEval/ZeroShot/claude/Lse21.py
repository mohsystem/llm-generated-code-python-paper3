
import sys

def add_thousand(value):
    return value + 1000

def main():
    # Test cases
    test_cases = [100, -500, 0, 9999, -1000]
    
    for test_case in test_cases:
        result = add_thousand(test_case)
        print(f"Input: {test_case}, Output: {result}")
    
    # Command line argument handling
    if len(sys.argv) > 1:
        try:
            value = int(sys.argv[1])
            result = add_thousand(value)
            print(result)
        except ValueError:
            print("Invalid input. Please provide a valid integer.", file=sys.stderr)
            sys.exit(1)
    
    return 0

if __name__ == "__main__":
    exit(main())
