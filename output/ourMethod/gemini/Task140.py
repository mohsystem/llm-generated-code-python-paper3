import typing

def calculate(num1: float, num2: float, operator: str) -> float:
    """
    Performs a basic arithmetic operation.

    Args:
        num1: The first operand.
        num2: The second operand.
        operator: The operator string (+, -, *, /).

    Returns:
        The result of the operation.

    Raises:
        ValueError: if the operator is invalid or if division by zero is attempted.
    """
    if not isinstance(operator, str) or len(operator) != 1:
        raise ValueError("Error: Invalid operator. Operator must be a single character string.")

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
        raise ValueError("Error: Invalid operator. Only +, -, *, / are allowed.")

def main():
    """Main function with test cases."""
    test_cases = [
        (10.0, 5.0, '+'),
        (15.0, 3.0, '*'),
        (7.5, 2.5, '-'),
        (12.0, 0.0, '/'),  # Division by zero case
        (10.0, 3.0, '%')   # Invalid operator case
    ]

    for i, (num1, num2, op) in enumerate(test_cases):
        print(f"Test Case {i+1}: {num1} {op} {num2}")
        try:
            result = calculate(num1, num2, op)
            print(f"Result: {result:.2f}\n")
        except ValueError as e:
            print(f"{e}\n")

if __name__ == "__main__":
    main()