from typing import Union

def persistence(num: int) -> int:
    """
    Calculates the multiplicative persistence of a positive number.

    Args:
        num: A positive integer.

    Returns:
        The number of times digits must be multiplied to reach a single digit.
    """
    count = 0
    while num >= 10:
        count += 1
        product = 1
        temp = num
        while temp > 0:
            product *= temp % 10
            temp //= 10
        num = product
    return count

if __name__ == '__main__':
    # 5 test cases
    print(f"Input: 39, Output: {persistence(39)}")      # Expected: 3
    print(f"Input: 999, Output: {persistence(999)}")    # Expected: 4
    print(f"Input: 4, Output: {persistence(4)}")        # Expected: 0
    print(f"Input: 25, Output: {persistence(25)}")      # Expected: 2 (2*5=10, 1*0=0)
    print(f"Input: 679, Output: {persistence(679)}")    # Expected: 5 (6*7*9=378, 3*7*8=168, 1*6*8=48, 4*8=32, 3*2=6)