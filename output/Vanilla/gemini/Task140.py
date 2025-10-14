import sys

def calculate(num1, num2, operator):
    """
    Performs a basic arithmetic operation.

    Args:
        num1 (float): The first number.
        num2 (float): The second number.
        operator (str): The operator (+, -, *, /).

    Returns:
        The result of the operation, or a string with an error message.
    """
    if operator == '+':
        return num1 + num2
    elif operator == '-':
        return num1 - num2
    elif operator == '*':
        return num1 * num2
    elif operator == '/':
        if num2 != 0:
            return num1 / num2
        else:
            return "Error: Division by zero is not allowed."
    else:
        return f"Error: Invalid operator '{operator}'."

def main():
    # Test Case 1: Addition
    num1_1, num2_1, op1 = 10, 5, '+'
    print(f"Test Case 1: {num1_1} {op1} {num2_1} = {calculate(num1_1, num2_1, op1)}")

    # Test Case 2: Subtraction
    num1_2, num2_2, op2 = 20.5, 10.5, '-'
    print(f"Test Case 2: {num1_2} {op2} {num2_2} = {calculate(num1_2, num2_2, op2)}")

    # Test Case 3: Multiplication
    num1_3, num2_3, op3 = 7, 8, '*'
    print(f"Test Case 3: {num1_3} {op3} {num2_3} = {calculate(num1_3, num2_3, op3)}")

    # Test Case 4: Division
    num1_4, num2_4, op4 = 100, 4, '/'
    print(f"Test Case 4: {num1_4} {op4} {num2_4} = {calculate(num1_4, num2_4, op4)}")

    # Test Case 5: Division by zero
    num1_5, num2_5, op5 = 15, 0, '/'
    print(f"Test Case 5: {num1_5} {op5} {num2_5} = {calculate(num1_5, num2_5, op5)}")

if __name__ == "__main__":
    main()