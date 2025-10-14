
def calculate(num1, num2, operator):
    """\n    Performs arithmetic operation on two numbers based on the operator.\n    \n    Args:\n        num1: First number (float or int)\n        num2: Second number (float or int)\n        operator: Arithmetic operator as string (+, -, *, /)\n    \n    Returns:\n        Result of the arithmetic operation\n    \n    Raises:\n        ValueError: If operator is invalid\n        ZeroDivisionError: If division by zero is attempted\n    """
    # Validate operator input (whitelist approach)
    if not isinstance(operator, str) or len(operator) != 1:
        raise ValueError("Invalid operator")
    
    # Validate numeric inputs
    try:
        num1 = float(num1)
        num2 = float(num2)
    except (ValueError, TypeError):
        raise ValueError("Invalid numeric input")
    
    if operator == '+':
        return num1 + num2
    elif operator == '-':
        return num1 - num2
    elif operator == '*':
        return num1 * num2
    elif operator == '/':
        # Secure division with zero-check
        if num2 == 0:
            raise ZeroDivisionError("Division by zero is not allowed")
        return num1 / num2
    else:
        raise ValueError("Invalid operator. Use +, -, *, or /")


if __name__ == "__main__":
    # Test case 1: Addition
    try:
        print(f"Test 1: 10 + 5 = {calculate(10, 5, '+')}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 2: Subtraction
    try:
        print(f"Test 2: 20 - 8 = {calculate(20, 8, '-')}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 3: Multiplication
    try:
        print(f"Test 3: 7 * 6 = {calculate(7, 6, '*')}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 4: Division
    try:
        print(f"Test 4: 15 / 3 = {calculate(15, 3, '/')}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test case 5: Division by zero (error handling)
    try:
        print(f"Test 5: 10 / 0 = {calculate(10, 0, '/')}")
    except Exception as e:
        print(f"Test 5 Error: {e}")
