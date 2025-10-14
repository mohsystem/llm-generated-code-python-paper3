import sys

def validate_pin(pin: str) -> bool:
    """
    Validates an ATM PIN.
    A valid PIN must be a string containing exactly 4 or 6 digits.

    Args:
        pin: The string to validate.

    Returns:
        True if the PIN is valid, False otherwise.
    """
    # Rule #1: Ensure all input is validated.
    # We check the type hint for string, though Python is dynamic.
    # The logic checks length and content.
    if not isinstance(pin, str):
        return False
        
    return (len(pin) == 4 or len(pin) == 6) and pin.isdigit()

def main():
    """Main function with test cases."""
    print("Running Python test cases...")
    test_cases = ["1234", "123456", "12345", "a234", "123"]
    for pin in test_cases:
        # Use repr() to show quotes around the string for clarity
        print(f"PIN: {repr(pin)} -> {validate_pin(pin)}")

if __name__ == "__main__":
    main()