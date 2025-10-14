def calculate(num1, num2, operator):
    """Performs a simple arithmetic operation."""
    if not isinstance(num1, (int, float)) or not isinstance(num2, (int, float)):
        raise TypeError("Error: Both numbers must be numeric.")
    
    if operator == '+':
        return num1 + num2
    elif operator == '-':
        return num1 - num2
    elif operator == '*':
        return num1 * num2
    elif operator == '/':
        if num2 == 0:
            raise ValueError("Error: Division by zero is not allowed.")
        return num1 / num2
    else:
        raise ValueError("Error: Invalid operator. Only +, -, *, / are supported.")

def main():
    """Main function with test cases."""
    test_cases = [
        (10.0, 5.0, '+'),
        (20.5, 4.5, '-'),
        (7.0, 6.0, '*'),
        (15.0, 4.0, '/'),
        (10.0, 0.0, '/')
    ]

    print("--- Python Test Cases ---")
    for i, (num1, num2, op) in enumerate(test_cases, 1):
        try:
            result = calculate(num1, num2, op)
            print(f"Test Case {i}: {num1} {op} {num2} = {result:.2f}")
        except (ValueError, TypeError) as e:
            print(f"Test Case {i}: {num1} {op} {num2} -> {e}")

if __name__ == "__main__":
    main()