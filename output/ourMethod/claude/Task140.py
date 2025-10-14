
from typing import Union


def calculate(num1: float, num2: float, operator: str) -> str:
    """\n    Performs arithmetic operation on two numbers.\n    \n    Args:\n        num1: First number\n        num2: Second number\n        operator: Operator (+, -, *, /)\n    \n    Returns:\n        Result as string or error message\n    """
    VALID_OPERATORS = {'+', '-', '*', '/'}
    
    if not isinstance(operator, str):
        return "Error: Operator must be a string"
    
    if not operator:
        return "Error: Operator cannot be empty"
    
    if operator not in VALID_OPERATORS:
        return "Error: Invalid operator. Use +, -, *, or /"
    
    try:
        num1 = float(num1)
        num2 = float(num2)
    except (ValueError, TypeError):
        return "Error: Invalid number format"
    
    if not (abs(num1) < float('inf')):
        return "Error: First number is invalid"
    
    if not (abs(num2) < float('inf')):
        return "Error: Second number is invalid"
    
    result: float
    
    if operator == '+':
        result = num1 + num2
    elif operator == '-':
        result = num1 - num2
    elif operator == '*':
        result = num1 * num2
    elif operator == '/':
        if num2 == 0.0:
            return "Error: Division by zero"
        result = num1 / num2
    else:
        return "Error: Invalid operator"
    
    if not (abs(result) < float('inf')):
        return "Error: Result is invalid"
    
    return f"{result:.6f}"


def main() -> None:
    """Test cases for the calculator function."""
    print(f"Test Case 1: 10 + 5 = {calculate(10, 5, '+')}")
    print(f"Test Case 2: 10 - 5 = {calculate(10, 5, '-')}")
    print(f"Test Case 3: 10 * 5 = {calculate(10, 5, '*')}")
    print(f"Test Case 4: 10 / 5 = {calculate(10, 5, '/')}")
    print(f"Test Case 5: 10 / 0 = {calculate(10, 0, '/')}")


if __name__ == "__main__":
    main()
