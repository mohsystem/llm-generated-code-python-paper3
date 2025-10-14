
def find_gcd(a, b):
    """\n    Function to find GCD using Euclidean algorithm\n    \n    Args:\n        a: First number (int or float)\n        b: Second number (int or float)\n    \n    Returns:\n        GCD of a and b\n    """
    # Input validation - convert to integers and handle negative numbers
    try:
        a = abs(int(a))
        b = abs(int(b))
    except (ValueError, TypeError):
        raise ValueError("Invalid input: numbers must be convertible to integers")
    
    # Handle edge case where both numbers are 0
    if a == 0 and b == 0:
        raise ValueError("GCD is undefined for both numbers being zero")
    
    # Euclidean algorithm
    while b != 0:
        temp = b
        b = a % b
        a = temp
    
    return a


def main():
    """Main function with test cases"""
    # Test case 1: Normal positive numbers
    print(f"Test 1 - GCD(48, 18): {find_gcd(48, 18)}")
    
    # Test case 2: One number is 0
    print(f"Test 2 - GCD(0, 5): {find_gcd(0, 5)}")
    
    # Test case 3: Same numbers
    print(f"Test 3 - GCD(100, 100): {find_gcd(100, 100)}")
    
    # Test case 4: Prime numbers (coprime)
    print(f"Test 4 - GCD(17, 19): {find_gcd(17, 19)}")
    
    # Test case 5: Large numbers with negative input
    print(f"Test 5 - GCD(-270, 192): {find_gcd(-270, 192)}")


if __name__ == "__main__":
    main()
