def persistence(num):
    """
    Calculates the multiplicative persistence of a positive number.
    Multiplicative persistence is the number of times you must multiply the digits
    in a number until you reach a single digit.

    Args:
        num: A non-negative integer.
    
    Returns:
        The multiplicative persistence of num.

    Raises:
        ValueError: if the input number is not a non-negative integer.
    """
    # Secure coding: Validate input type and range.
    if not isinstance(num, int) or num < 0:
        raise ValueError("Input must be a non-negative integer.")

    count = 0
    while num >= 10:
        count += 1
        product = 1
        temp_num = num
        while temp_num > 0:
            product *= temp_num % 10
            temp_num //= 10
        num = product
    return count

if __name__ == "__main__":
    # 5 Test Cases
    print(f"persistence(39) -> {persistence(39)}")      # Expected: 3
    print(f"persistence(999) -> {persistence(999)}")    # Expected: 4
    print(f"persistence(4) -> {persistence(4)}")        # Expected: 0
    print(f"persistence(25) -> {persistence(25)}")      # Expected: 2 (2*5=10, 1*0=0)
    print(f"persistence(679) -> {persistence(679)}")    # Expected: 5 (6*7*9=378, 3*7*8=168, 1*6*8=48, 4*8=32, 3*2=6)