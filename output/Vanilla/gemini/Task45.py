import sys

def divide_strings(a, b):
    """
    Attempts to convert two strings to floats and divide the first by the second.
    Handles potential ValueError (invalid number format) and ZeroDivisionError.

    Args:
        a: The numerator as a string.
        b: The denominator as a string.

    Returns:
        The result of the division as a float, or None if an error occurred.
    """
    try:
        numerator = float(a)
        denominator = float(b)
        result = numerator / denominator
        return result
    except ValueError:
        print("Error: Invalid number format. Could not convert string to float.", file=sys.stderr)
        return None
    except ZeroDivisionError:
        print("Error: Division by zero is not allowed.", file=sys.stderr)
        return None
    except Exception as e:
        # A general catch-all for any other unexpected errors
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None

def main():
    print("--- Python Test Cases ---")

    # Test Case 1: Valid division
    print("\nTest Case 1: divide_strings(\"10\", \"2\")")
    result1 = divide_strings("10", "2")
    if result1 is not None:
        print(f"Result: {result1}")

    # Test Case 2: Division by zero
    print("\nTest Case 2: divide_strings(\"5\", \"0\")")
    result2 = divide_strings("5", "0")
    if result2 is not None:
        print(f"Result: {result2}")

    # Test Case 3: Invalid numerator
    print("\nTest Case 3: divide_strings(\"abc\", \"5\")")
    result3 = divide_strings("abc", "5")
    if result3 is not None:
        print(f"Result: {result3}")

    # Test Case 4: Invalid denominator
    print("\nTest Case 4: divide_strings(\"10\", \"xyz\")")
    result4 = divide_strings("10", "xyz")
    if result4 is not None:
        print(f"Result: {result4}")

    # Test Case 5: Valid floating-point division
    print("\nTest Case 5: divide_strings(\"7.5\", \"2.5\")")
    result5 = divide_strings("7.5", "2.5")
    if result5 is not None:
        print(f"Result: {result5}")

if __name__ == "__main__":
    main()