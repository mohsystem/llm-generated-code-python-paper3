def factorial(n):
    """
    Calculates the factorial of a non-negative integer.
    :param n: The number to calculate the factorial of.
    :return: The factorial of n, or an error message if n is negative.
    """
    if n < 0:
        return "Factorial does not exist for negative numbers"
    elif n == 0:
        return 1
    else:
        result = 1
        for i in range(1, n + 1):
            result *= i
        return result

def main():
    """Main function to run test cases."""
    print("Python Factorial Test Cases:")
    test_cases = [0, 1, 5, 10, 15]
    for test in test_cases:
        print(f"Factorial of {test} is {factorial(test)}")

if __name__ == "__main__":
    main()