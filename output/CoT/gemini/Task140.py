def calculate(num1, num2, operator):
    """
    Performs a basic arithmetic operation on two numbers.

    Args:
        num1 (float): The first number.
        num2 (float): The second number.
        operator (str): The operator character (+, -, *, /).

    Returns:
        float: The result of the operation.

    Raises:
        ValueError: If the operator is invalid or if division by zero is attempted.
    """
    if operator == '+':
        return num1 + num2
    elif operator == '-':
        return num1 - num2
    elif operator == '*':
        return num1 * num2
    elif operator == '/':
        if num2 == 0:
            raise ValueError("Division by zero is not allowed.")
        return num1 / num2
    else:
        raise ValueError(f"Invalid operator: {operator}")

if __name__ == "__main__":
    # Test Case 1: Addition
    try:
        print(f"Test 1: 10.5 + 2.5 = {calculate(10.5, 2.5, '+')}")
    except ValueError as e:
        print(f"Test 1 Error: {e}")

    # Test Case 2: Subtraction
    try:
        print(f"Test 2: 20.0 - 5.5 = {calculate(20.0, 5.5, '-')}")
    except ValueError as e:
        print(f"Test 2 Error: {e}")

    # Test Case 3: Multiplication
    try:
        print(f"Test 3: 5.0 * 4.0 = {calculate(5.0, 4.0, '*')}")
    except ValueError as e:
        print(f"Test 3 Error: {e}")

    # Test Case 4: Division by Zero (Error)
    try:
        print(f"Test 4: 10.0 / 0.0 = {calculate(10.0, 0.0, '/')}")
    except ValueError as e:
        print(f"Test 4 Error: {e}")

    # Test Case 5: Invalid Operator (Error)
    try:
        print(f"Test 5: 10.0 % 5.0 = {calculate(10.0, 5.0, '%')}")
    except ValueError as e:
        print(f"Test 5 Error: {e}")