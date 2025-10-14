
def calculate(num1, num2, operator):
    if operator == '+':
        return num1 + num2
    elif operator == '-':
        return num1 - num2
    elif operator == '*':
        return num1 * num2
    elif operator == '/':
        if num2 == 0:
            print("Error: Division by zero")
            return None
        return num1 / num2
    else:
        print("Error: Invalid operator")
        return None

if __name__ == "__main__":
    # Test case 1: Addition
    print(f"Test 1 (10 + 5): {calculate(10, 5, '+')}")
    
    # Test case 2: Subtraction
    print(f"Test 2 (10 - 5): {calculate(10, 5, '-')}")
    
    # Test case 3: Multiplication
    print(f"Test 3 (10 * 5): {calculate(10, 5, '*')}")
    
    # Test case 4: Division
    print(f"Test 4 (10 / 5): {calculate(10, 5, '/')}")
    
    # Test case 5: Division by zero
    print(f"Test 5 (10 / 0): ", end="")
    calculate(10, 0, '/')
