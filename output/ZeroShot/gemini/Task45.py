import math

def perform_division(num_str1, num_str2):
    """
    Securely converts two string inputs to floats and performs division.
    It handles None/empty inputs, non-numeric formats, and division by zero.

    Args:
        num_str1: The string representing the numerator.
        num_str2: The string representing the denominator.

    Returns:
        The result of the division as a float, or math.nan if an error occurs.
    """
    try:
        # 1. Validate for None or empty inputs
        if not num_str1 or not num_str2:
            raise ValueError("Input strings cannot be None or empty.")

        # 2. Convert strings to numbers, handling format errors
        numerator = float(num_str1)
        denominator = float(num_str2)

        # 3. Check for division by zero (handled by ZeroDivisionError)
        result = numerator / denominator
        return result

    except ValueError as e:
        # Catches errors from float() for invalid formats or our custom error
        print(f"Error: Invalid input provided. Details: {e}")
        return math.nan
    except ZeroDivisionError:
        # Catches division by zero
        print("Error: Cannot divide by zero.")
        return math.nan
    except Exception as e:
        # A general catch-all for any other unexpected errors
        print(f"An unexpected error occurred: {e}")
        return math.nan

def main():
    # --- Test Cases ---
    test_cases = [
        ("100", "20"),      # Test Case 1: Valid input
        ("10", "0"),        # Test Case 2: Division by zero
        ("abc", "5"),       # Test Case 3: Invalid number format
        ("50", None),       # Test Case 4: None input
        ("", "10")          # Test Case 5: Empty string input
    ]

    for i, (n1, n2) in enumerate(test_cases, 1):
        print(f"Test Case {i}: Valid input ('{n1}', '{n2}')")
        result = perform_division(n1, n2)
        if not math.isnan(result):
            print(f"Result: {result}")
        print("--------------------")

if __name__ == "__main__":
    main()