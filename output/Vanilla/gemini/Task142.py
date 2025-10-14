def gcd(a, b):
    """
    Finds the greatest common divisor (GCD) of two numbers using the Euclidean algorithm.
    :param a: The first number.
    :param b: The second number.
    :return: The greatest common divisor of a and b.
    """
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

if __name__ == "__main__":
    # Test cases
    print("Python Test Cases:")
    print(f"GCD(48, 18) = {gcd(48, 18)}")         # Expected: 6
    print(f"GCD(101, 103) = {gcd(101, 103)}")   # Expected: 1
    print(f"GCD(56, 98) = {gcd(56, 98)}")       # Expected: 14
    print(f"GCD(270, 192) = {gcd(270, 192)}")   # Expected: 6
    print(f"GCD(15, 0) = {gcd(15, 0)}")         # Expected: 15