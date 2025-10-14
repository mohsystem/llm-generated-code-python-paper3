
def is_narcissistic(number):
    # Input validation - ensure positive integer
    if number < 0:
        return False
    
    # Convert to string to get digits
    num_str = str(number)
    num_digits = len(num_str)
    
    # Calculate sum of digits raised to power of digit count
    total = 0
    for digit_char in num_str:
        digit = int(digit_char)
        total += digit ** num_digits
    
    return total == number


if __name__ == "__main__":
    # Test cases
    print(f"Test 1 - 153: {is_narcissistic(153)}")  # True
    print(f"Test 2 - 1652: {is_narcissistic(1652)}")  # False
    print(f"Test 3 - 9: {is_narcissistic(9)}")  # True
    print(f"Test 4 - 9474: {is_narcissistic(9474)}")  # True
    print(f"Test 5 - 370: {is_narcissistic(370)}")  # True
