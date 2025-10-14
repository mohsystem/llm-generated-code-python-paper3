
def is_narcissistic(value: int) -> bool:
    """Check if a number is narcissistic."""
    # Validate input is positive integer
    if not isinstance(value, int) or value < 0:
        raise ValueError("Input must be a positive integer")
    
    # Convert to string to get digits safely
    num_str = str(value)
    num_digits = len(num_str)
    
    # Validate length to prevent excessive computation
    if num_digits > 20:
        return False
    
    total = 0
    for char in num_str:
        if not char.isdigit():
            raise ValueError("Invalid digit in number")
        digit = int(char)
        # Calculate power safely
        power = digit ** num_digits
        total += power
        # Check for overflow (Python handles big ints, but check reasonableness)
        if total > 10 ** 20:
            return False
    
    return total == value


def main():
    """Test cases for narcissistic number checker."""
    # Test cases
    print(is_narcissistic(7) == True)      # 7^1 = 7
    print(is_narcissistic(153) == True)    # 1^3 + 5^3 + 3^3 = 153
    print(is_narcissistic(1652) == False)  # Not narcissistic
    print(is_narcissistic(9474) == True)   # 9^4 + 4^4 + 7^4 + 4^4 = 9474
    print(is_narcissistic(100) == False)   # Not narcissistic


if __name__ == "__main__":
    main()
