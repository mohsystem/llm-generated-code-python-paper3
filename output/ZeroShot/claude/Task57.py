
def factorial(n):
    if n < 0:
        raise ValueError("Factorial is not defined for negative numbers")
    if n == 0 or n == 1:
        return 1
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result

if __name__ == "__main__":
    # Test case 1
    print(f"Factorial of 0: {factorial(0)}")
    
    # Test case 2
    print(f"Factorial of 1: {factorial(1)}")
    
    # Test case 3
    print(f"Factorial of 5: {factorial(5)}")
    
    # Test case 4
    print(f"Factorial of 10: {factorial(10)}")
    
    # Test case 5
    print(f"Factorial of 15: {factorial(15)}")
