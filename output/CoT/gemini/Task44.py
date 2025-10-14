import sys

def perform_operation(num1, num2, operator):
    """
    Performs a basic arithmetic operation after validating inputs.

    Args:
        num1 (int): The first integer.
        num2 (int): The second integer.
        operator (str): The character representing the operation (+, -, *, /).

    Returns:
        str: A string representing the result or an error message.
    """
    # Security: Validate the operator is one of the allowed characters.
    if operator not in ['+', '-', '*', '/']:
        return f"Error: Invalid operator '{operator}'."

    # Security: Validate against division by zero.
    if operator == '/' and num2 == 0:
        return "Error: Division by zero is not allowed."

    try:
        # Ensure inputs are integers before operation
        n1 = int(num1)
        n2 = int(num2)

        if operator == '+':
            result = n1 + n2
        elif operator == '-':
            result = n1 - n2
        elif operator == '*':
            result = n1 * n2
        elif operator == '/':
            result = n1 / n2
        
        return f"{n1} {operator} {n2} = {result:.2f}"

    except ValueError:
        return "Error: Inputs must be valid integers."
    except Exception as e:
        return f"An unexpected error occurred: {e}"


def main():
    """Main function to run test cases and an optional interactive demo."""
    # --- Test Cases ---
    print("--- Running Automated Test Cases ---")

    # Test Case 1: Addition
    print("Test Case 1 (Addition):")
    print("Input: 10, 5, '+'")
    print(f"Output: {perform_operation(10, 5, '+')}\n")

    # Test Case 2: Subtraction
    print("Test Case 2 (Subtraction):")
    print("Input: 10, 15, '-'")
    print(f"Output: {perform_operation(10, 15, '-')}\n")
    
    # Test Case 3: Valid Division
    print("Test Case 3 (Valid Division):")
    print("Input: 20, 4, '/'")
    print(f"Output: {perform_operation(20, 4, '/')}\n")

    # Test Case 4: Invalid Division (by zero)
    print("Test Case 4 (Division by Zero):")
    print("Input: 10, 0, '/'")
    print(f"Output: {perform_operation(10, 0, '/')}\n")

    # Test Case 5: Invalid Operator
    print("Test Case 5 (Invalid Operator):")
    print("Input: 7, 8, '%'")
    print(f"Output: {perform_operation(7, 8, '%')}\n")

    # --- Interactive Section (Example of secure input handling) ---
    # To run interactively, call this function:
    # run_interactive_session()
    
def run_interactive_session():
    """Handles secure interactive user input."""
    print("\n--- Starting Interactive Session ---")
    
    # Securely read first integer
    while True:
        try:
            num1_str = input("Enter first integer: ")
            num1 = int(num1_str)
            break
        except ValueError:
            print("Error: Invalid input. Please enter a valid integer.")

    # Securely read second integer
    while True:
        try:
            num2_str = input("Enter second integer: ")
            num2 = int(num2_str)
            break
        except ValueError:
            print("Error: Invalid input. Please enter a valid integer.")
    
    # Securely read operator
    while True:
        operator = input("Enter an operator (+, -, *, /): ").strip()
        if operator in ['+', '-', '*', '/']:
            break
        else:
            print("Error: Invalid operator. Please use +, -, *, or /.")
            
    print(f"Result: {perform_operation(num1, num2, operator)}")


if __name__ == "__main__":
    main()