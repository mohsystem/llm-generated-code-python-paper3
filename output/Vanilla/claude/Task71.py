
import sys

def convert_to_integer(input_str):
    try:
        return int(input_str.strip())
    except ValueError:
        return None

def main():
    test_cases = ["123", "-456", "0", "abc", "12.34"]
    
    if len(sys.argv) > 1:
        result = convert_to_integer(sys.argv[1])
        if result is not None:
            print(f"Converted integer: {result}")
        else:
            print(f"Invalid integer input: {sys.argv[1]}")
    else:
        print("Running test cases:")
        for test_case in test_cases:
            result = convert_to_integer(test_case)
            if result is not None:
                print(f"Input: '{test_case}' -> Output: {result}")
            else:
                print(f"Input: '{test_case}' -> Output: Invalid (cannot convert)")

if __name__ == "__main__":
    main()
